rule Windows_VulnDriver_NCR_d77e8532 {
    meta:
        author = "Elastic Security"
        id = "d77e8532-82af-4f19-a122-de172bf000f0"
        fingerprint = "4f808bfa7573440a2158713f8bff34dc7eb69ea90500b4234c29561ceb12a5ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NCR Corporation, Version: <= 2.20.0.7"
        threat_name = "Windows.VulnDriver.NCR"
        reference_sample = "0f30ecd4faec147a2335a4fc031c8a1ac9310c35339ebeb651eb1429421951a0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 43 52 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 61 00 64 00 48 00 77 00 4D 00 67 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x13][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x14-\x14][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x06][\x00-\x00][\x00-\x00][\x00-\x00]|[\x14-\x14][\x00-\x00][\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RadHwMgr.pdb"
        $str2 = "IOCTL_RADHWMGR_READ_IO"
        $str3 = "Radiant Systems, Inc.  Hardware Manager driver" wide
        $str4 = "Radiant Hardware Manager for P15xx Platform" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}