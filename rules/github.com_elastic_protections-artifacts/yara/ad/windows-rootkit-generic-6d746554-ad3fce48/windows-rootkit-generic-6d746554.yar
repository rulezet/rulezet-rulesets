rule Windows_Rootkit_Generic_6d746554 {
    meta:
        author = "Elastic Security"
        id = "6d746554-db20-41cd-9480-81d245859eca"
        fingerprint = "0a63d8b23efbbd8ceee2c8acb90c7f7b456bd6d17d04e7331c522eeb5262f19c"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "4f412f9aa89994cda45422d23d6d961809225de9a4f5a8bfbfb9ac0e8725917e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "F:\\Source Codes\\IceCubes-Driver\\x64\\Release\\Windows-Ice-Monitor.pdb"
        $seq1 = { B8 4F EC C4 4E 41 F7 E0 C1 EA 05 0F B7 C2 6B C8 68 41 0F B7 C0 41 FF C0 66 2B C1 66 83 C0 62 66 41 31 01 4D 8D 49 02 41 83 F8 17 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}