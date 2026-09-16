rule Windows_VulnDriver_ComputerZ_154a8ae4 {
    meta:
        author = "Elastic Security"
        id = "154a8ae4-6471-4ccb-8fef-fd645c8b0ed9"
        fingerprint = "aa1483bc3d84fe3d01b11e6c088e72a9613df780fcb9842012c28b9c21bac514"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Qihoo 360 Software (Beijing) Company Limited, Version: <= 1.6.16.1015"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "03680068ec41bbe725e1ed2042b63b82391f792e8e21e45dc114618641611d5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 69 68 6F 6F 20 33 36 30 20 53 6F 66 74 77 61 72 65 20 28 42 65 69 6A 69 6E 67 29 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0f][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf6][\x03-\x03])[\x10-\x10][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xf7-\xf7][\x03-\x03][\x10-\x10][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}