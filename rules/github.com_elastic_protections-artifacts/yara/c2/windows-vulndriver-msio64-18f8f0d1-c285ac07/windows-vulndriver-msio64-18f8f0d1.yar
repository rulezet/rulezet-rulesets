rule Windows_VulnDriver_MsIo64_18f8f0d1 {
    meta:
        author = "Elastic Security"
        id = "18f8f0d1-8110-4db7-a9f3-05d8a8bd7777"
        fingerprint = "e27524c8f897fd8f7e359fff45182441a1d567a8c258b1b28a3904a09346ea06"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.3.23.406"
        threat_name = "Windows.VulnDriver.MsIo64"
        reference_sample = "d636c011b8b2896572f5de260eb997182cc6955449b044a739bd19cbe6fdabd2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 73 00 49 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x95][\x01-\x01])[\x17-\x17][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x96-\x96][\x01-\x01][\x17-\x17][\x00-\x00])/
        $str1 = "MsIo64.pdb"
        $str2 = "IOCTL_MSIO_MAPPHYSTOLIN"
        $str3 = "MsIo64 Driver Version 1.3" wide
        $str4 = "MICSYS IO driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}