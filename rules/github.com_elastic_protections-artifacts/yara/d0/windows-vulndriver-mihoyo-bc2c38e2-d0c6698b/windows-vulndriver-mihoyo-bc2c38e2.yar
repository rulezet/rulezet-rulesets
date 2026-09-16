rule Windows_VulnDriver_Mihoyo_bc2c38e2 {
    meta:
        author = "Elastic Security"
        id = "bc2c38e2-f16a-4d2a-9434-19359606d669"
        fingerprint = "1e4ea724d64aae4d7dd792eb7436d683f20ace3eff956c9bddccfc8b6e6ef227"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "8bf84bed9b5fa4576182c84d2f31679dc472acd0f83c9813498e9f71ed9fef3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 49 89 40 08 66 41 0F B6 C2 48 98 9C 48 C1 D0 FF 66 41 0F B6 C1 41 8F 00 49 81 EB 04 00 00 00 66 41 03 C4 41 8B 03 66 41 85 D9 33 C6 E9 65 65 0D 00 }
        $seq2 = { 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 6B 00 6D 00 6C 00 6F 00 67 00 2E 00 6C 00 6F 00 67 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}