rule Windows_VulnDriver_HP_5c96add5 {
    meta:
        author = "Elastic Security"
        id = "5c96add5-b522-4d58-8f9d-027d1c4b8198"
        fingerprint = "3ce1434611c78dee61d5874f347375fecaa39090d25c9bf28aa3e91f43d393c8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "725d4445c65e1bf94c9fc8f07961512a8ad22628515bfa789b321a3169e0b65a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 53 00 50 00 4F 00 52 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SSPORT.pdb"
        $str2 = "Port Contention Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}