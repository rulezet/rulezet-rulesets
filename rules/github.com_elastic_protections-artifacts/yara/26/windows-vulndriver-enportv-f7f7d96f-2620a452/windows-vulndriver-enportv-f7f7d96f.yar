rule Windows_VulnDriver_EnPortv_f7f7d96f {
    meta:
        author = "Elastic Security"
        id = "f7f7d96f-60a5-442e-9e25-03334a6e8f4d"
        fingerprint = "8c3a8efa9c88ea6785620b226baf265f5569794d2ec7f5bc4d11ba4d1a1efde3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Guidance Software, Inc., Version: <= 1.60.0.0"
        threat_name = "Windows.VulnDriver.EnPortv"
        reference_sample = "030ec373e4eb92592cbfc5e590ddbcbc5ece2d43809b141bb3fffceb0e01f72e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 75 69 64 61 6E 63 65 20 53 6F 66 74 77 61 72 65 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6E 00 50 00 6F 00 72 00 74 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3b][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3c-\x3c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "EnData.pdb"
        $str2 = "EnCase Driver" wide
        $str3 = "EnCase Driver for WinNET 64 bit Svn Rev:76306 with EnCase 7.9.1.53" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}