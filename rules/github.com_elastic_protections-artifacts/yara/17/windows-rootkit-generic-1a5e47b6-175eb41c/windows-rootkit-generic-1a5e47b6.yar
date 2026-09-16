rule Windows_Rootkit_Generic_1a5e47b6 {
    meta:
        author = "Elastic Security"
        id = "1a5e47b6-c297-4c52-8cd4-66b64afe29cd"
        fingerprint = "fd0ec05cf03de2e1fe2305781cf926af57ec72264a1d4f93194bf9113248cc95"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "e8b1a0ddc7a4404eb3c46217e07b5ed91723f44464a6ef589634aeb4fb8f5666"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $seq1 = { 53 56 57 BB 55 55 00 00 33 FF EB 5E 33 F6 66 8B 31 0F B7 C6 C1 E8 06 83 F8 01 8D 1C 9F 7C 58 83 F8 03 7F 53 8B D6 33 D3 2B D7 2A D0 83 E2 3F 8B C2 33 D2 66 3D 0A 00 73 05 8D 50 30 EB 09 }
        $seq2 = { F6 C3 01 74 02 33 D1 8B C1 C1 E8 1F D1 E1 85 C0 74 06 81 F1 E9 35 79 35 }
        $seq3 = { 3B CB 74 52 81 F9 84 20 01 AA 74 4A 81 F9 88 20 01 AA 74 36 81 F9 C0 20 01 AA 74 25 81 F9 C4 20 01 AA 75 09 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $seq1 and $seq2 and $seq3
}