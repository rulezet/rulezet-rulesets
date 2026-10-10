rule Windows_Hacktool_Generic_45b88d7a {
    meta:
        author = "Elastic Security"
        id = "45b88d7a-1eb3-41a8-821b-378fe745aa9d"
        fingerprint = "7ee9fa5ea1f7a33ec44076ba0cc3fb9fae8fc7bb67e12af92ae3f325f63bfed9"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "C:\\src\\x64\\Release\\AltWinSock2DLL.pdb" wide fullword
        $seq_1 = { 48 8D 05 B7 61 01 00 48 8B D7 48 89 44 24 28 4C 8D 8D 70 01 00 00 48 8D 45 60 4C 8D 05 B1 61 01 00 48 89 44 24 20 48 8D 4C 24 50 E8 2E 01 00 00 }
        $seq_2 = { 00 28 06 00 00 06 26 12 00 1D 28 0E 00 00 0A 1F F5 28 04 00 00 06 0B 72 01 00 00 70 28 0F 00 00 0A 00 28 10 00 00 0A 0C 00 08 28 02 00 00 06 28 11 00 00 0A 00 00 DE 11 }
        $seq_3 = { 48 89 54 24 10 48 89 4C 24 08 48 81 EC F8 00 00 00 48 C7 44 24 28 00 00 00 00 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 74 01 00 00 33 D2 33 C9 FF 15 0A DF 00 00 C7 44 24 30 B8 00 00 00 48 C7 44 24 38 00 00 00 00 48 8D 05 E2 01 00 00 48 89 44 24 40 48 8D 05 F6 01 00 00 48 89 44 24 48 48 8D 05 0A 02 00 00 48 89 44 24 50 48 8D 05 CE FE FF FF 48 89 44 24 58 48 8D 05 E2 FE FF FF 48 89 44 24 60 48 8D 05 06 02 00 00 48 89 44 24 68 48 8D 05 EA FE FF FF 48 89 44 24 70 48 C7 44 24 78 00 00 00 00 48 C7 84 24 80 00 00 00 00 00 00 00 48 C7 84 24 88 00 00 00 00 00 00 00 48 C7 84 24 90 00 00 00 00 00 00 00 48 C7 84 24 98 00 00 00 00 00 00 00 48 C7 84 24 A0 00 00 00 00 00 00 00 48 8D 05 B9 FE FF FF 48 89 84 24 A8 00 00 00 48 8D 05 CA FE FF FF 48 89 84 24 B0 00 00 00 48 8D 05 DB FE FF FF 48 89 84 24 B8 00 00 00 48 8D 05 9C 01 00 00 48 89 84 24 C0 00 00 00 48 C7 84 24 C8 00 00 00 00 00 00 00 48 8D 05 91 01 00 00 48 89 84 24 D0 00 00 00 48 8D 05 A2 01 00 00 48 89 84 24 D8 00 00 00 48 8D 05 B3 01 00 00 48 89 84 24 E0 00 00 00 48 8D 44 24 30 48 81 C4 F8 00 00 00 C3 }
    condition:
        1 of them
}