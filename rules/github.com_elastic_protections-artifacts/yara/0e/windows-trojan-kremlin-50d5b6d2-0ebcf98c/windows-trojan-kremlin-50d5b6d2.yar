rule Windows_Trojan_Kremlin_50d5b6d2 {
    meta:
        author = "Elastic Security"
        id = "50d5b6d2-230f-413b-81db-adf019770feb"
        fingerprint = "d0c3e59d57e1da50e9e77dc27d333dae4644d01315758cafeb5e8962490dc9ef"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "0553ef3338bf99f17c185706381ee546989fc2dedae627ef222b3d50befbe9d5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 48 85 C0 74 2E 48 8D 94 24 [4] 48 8D 8C 24 A0 13 00 00 E8 [4] 85 C0 74 15 }
        $a1 = { 48 85 C0 74 2E 48 8D 94 24 [4] 48 8D 8C 24 F0 05 00 00 E8 [4] 85 C0 74 15 }
        $a2 = { 48 85 C0 74 30 48 8D 94 24 [4] 48 8D 8C 24 F0 05 00 00 E8 [4] 85 C0 74 17 }
        $a3 = { 83 7C 24 58 00 75 2F 48 8D 94 24 [4] 48 8D 8C 24 50 0D 00 00 E8 [4] 48 8B C8 E8 [4] 89 44 24 58 }
        $a4 = { 0F B6 C0 85 C0 74 15 48 8D 8C 24 48 08 00 00 E8 [4] C7 44 24 38 01 00 00 00 }
        $a5 = { 0F B6 C0 85 C0 74 15 48 8D 8C 24 C0 06 00 00 E8 [4] C7 44 24 30 01 00 00 00 }
        $a6 = { 83 7C 24 48 00 74 ?? 83 7C 24 48 02 74 ?? 44 8B 4C 24 48 }
        $a7 = { 83 7C 24 5C 00 0F 84 [4] 83 BC 24 C0 18 00 00 00 0F 85 }
    condition:
        2 of them
}