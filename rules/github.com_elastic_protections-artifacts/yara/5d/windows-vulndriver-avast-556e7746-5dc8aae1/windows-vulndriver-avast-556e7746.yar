rule Windows_VulnDriver_Avast_556e7746 {
    meta:
        author = "Elastic Security"
        id = "556e7746-71f0-46ef-8bf3-e4b0b5ee92a0"
        fingerprint = "785ba92ff13b0649dad55843bbd3d50ffda30da0ee197318fb1081eeda4ebb9b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Netherlands B.V., Version: <= 18.3.3860.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "2594b3ef3675ca3a7b465b8ed4962e3251364bab13b12af00ebba7fa2211abb2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 4E 65 74 68 65 72 6C 61 6E 64 73 20 42 2E 56 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x13][\x0f-\x0f])|[\x03-\x03][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\x00][\x00-\x00][\x14-\x14][\x0f-\x0f])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}