rule Windows_VulnDriver_Mihoyo_a1811a83 {
    meta:
        author = "Elastic Security"
        id = "a1811a83-2c4d-4bc0-81ee-d558b810d5f0"
        fingerprint = "1e1e8772bdcf658f0f249507a120d9eab1f882aeffccb031400f4c0be2278200"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: miHoYo Co.,Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "f7d72d22cd4ad3e44fd617bdb4c90b9a884f4eb045688c0e3fb64dd33e033eaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 4D 8B 0A 47 8B 44 0B 08 47 33 04 0B 4C 23 C7 4F 33 04 0B 49 8B C8 49 D1 E8 83 E1 01 48 8B 14 CE 4B 33 94 0B 20 FB FF FF 49 33 D0 4B 89 14 0B 49 83 C3 08 49 81 FB B8 09 00 00 7C C4 4D 8B 0A 45 8B 81 B8 09 00 00 45 33 01 4C 23 C7 4D 33 81 B8 09 00 00 49 8B C8 49 D1 E8 83 E1 01 48 8B 14 CE 49 33 91 D8 04 00 00 49 33 D0 49 89 91 B8 09 00 00 41 83 62 08 00 45 33 C0 }
        $seq2 = { 73 DB 0F B7 C1 48 C1 E0 06 4C 8B 44 38 48 45 84 F6 75 17 48 8D 05 0E 01 00 00 4C 3B C0 75 17 33 C9 E8 8A 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}