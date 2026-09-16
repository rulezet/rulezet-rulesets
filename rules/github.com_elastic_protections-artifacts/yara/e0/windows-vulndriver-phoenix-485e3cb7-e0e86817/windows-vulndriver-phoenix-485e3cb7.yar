rule Windows_VulnDriver_Phoenix_485e3cb7 {
    meta:
        author = "Elastic Security"
        id = "485e3cb7-b21f-44cc-a820-cb4f9a1b0d36"
        fingerprint = "ab9a01d2c89d7b73bbbf9b9643076e2cd03ac374a1d3cb61800aaec23928c388"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "6948480954137987a0be626c24cf594390960242cd75f094cd6aaa5c2e7a54fa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 67 00 65 00 6E 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Agent64.pdb"
        $str2 = "DriverAgent" wide
        $str3 = "DriverAgent Direct I/O for 64-bit Windows" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}