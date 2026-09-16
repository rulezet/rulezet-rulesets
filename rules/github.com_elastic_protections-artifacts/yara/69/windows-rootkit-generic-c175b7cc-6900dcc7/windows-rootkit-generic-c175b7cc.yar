rule Windows_Rootkit_Generic_c175b7cc {
    meta:
        author = "Elastic Security"
        id = "c175b7cc-336e-4672-9ed8-042fa06c315e"
        fingerprint = "f1dd833336500bc1aaabf32795539ae409a9b4464021b647992098640959625f"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 12980215 Canada Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f6d7faddc3a56875a8d24e4785a139141dd892968f70bf0e37d505af9a3324fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 31 32 39 38 30 32 31 35 20 43 61 6E 61 64 61 20 49 6E 63 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 4C 8B C0 49 D3 F1 66 C1 C1 76 49 89 06 48 F7 D8 66 98 0F 31 4D 0F BF CD 48 C1 E2 20 E9 00 00 00 00 4C 8B CF C6 C5 64 48 0B C2 49 8B CF 49 89 00 8B D5 40 80 FD 4A F9 49 83 C0 08 89 5F 08 E9 00 00 00 00 }
        $seq2 = { 68 B4 F6 E3 D5 E8 00 CF F7 FF 6E 68 44 30 70 6E E8 42 7E F3 FF 6A 68 BC 42 FB D5 E8 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}