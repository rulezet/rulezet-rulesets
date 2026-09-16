rule Windows_Rootkit_Generic_c819f0a8 {
    meta:
        author = "Elastic Security"
        id = "c819f0a8-b8a4-40f4-9dae-2793387f3d41"
        fingerprint = "4c45366cd892f0dbbd3457f510531539aa3f779e2d168aca3276ac4cbffecd69"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 1.A Connect GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "6709a2d7925248fe172e9bc5495f45b9bb74060c43e1c58e671f0e6c434fd82b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 31 2E 41 20 43 6F 6E 6E 65 63 74 20 47 6D 62 48 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 0F 9D C1 49 8D 4E 08 4C 8B C0 F6 D0 66 99 4C 8D 4C 24 20 49 8B 06 48 63 D5 49 0F BF D7 48 89 47 10 48 0F CA 89 5F 08 49 0F B7 D7 49 0F 44 D3 66 40 0F B6 D5 0F 10 07 41 0F 40 D2 0F B7 D3 41 0F BF D6 8B 16 0F 10 4F 10 0F 29 44 24 20 F2 0F 10 47 20 F2 0F 11 44 24 40 E9 00 00 00 00 }
        $seq2 = { 41 B8 FD FF FF FF C7 45 B8 FC FF FF FF 83 C9 FF C6 45 BC D1 44 89 45 C0 48 8B FB C6 45 C4 48 41 8D 50 01 C6 45 CC 8B 8D 42 FD 89 55 C8 89 45 98 89 44 24 78 89 44 24 38 89 44 24 58 8B 05 00 4D 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}