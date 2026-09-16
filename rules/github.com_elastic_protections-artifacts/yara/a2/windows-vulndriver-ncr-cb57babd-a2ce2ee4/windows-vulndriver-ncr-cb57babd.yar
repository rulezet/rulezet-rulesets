rule Windows_VulnDriver_NCR_cb57babd {
    meta:
        author = "Elastic Security"
        id = "cb57babd-9c7b-4ff2-9f11-f41bf30b8e23"
        fingerprint = "7cef0bae1ae6dbc708cc1f95b8b7c9fcb484a02ce950c2b1dbc456db7d1b165a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.33.0.0"
        threat_name = "Windows.VulnDriver.NCR"
        reference_sample = "7c8ad57b3a224fdc2aac9dd2d7c3624f1fcd3542d4db804de25a90155657e2cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 61 00 64 00 48 00 77 00 4D 00 67 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x20][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x21-\x21][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RadHwMgr.pdb"
        $str2 = "IOCTL_RADHWMGR_READ_IO"
        $str3 = "NCR Corporation Hardware Manager driver" wide
        $str4 = "Radiant Hardware Manager for P15xx Platform" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}