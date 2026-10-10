rule Windows_Trojan_Kremlin_c241b245 {
    meta:
        author = "Elastic Security"
        id = "c241b245-2d29-4f8e-a8f0-cc4b252414e7"
        fingerprint = "d26cf2b8a4697669bbf740458e10e9212bd9efadf9f075ad2d56c0645b57c7aa"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "4f48cb6909213f851ac99074815b0be7ad746efff9dfb2c579fc8426397eae57"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 48 85 C0 0F 84 [4] 48 8D 95 78 03 00 00 48 8D 8D F8 03 00 00 E8 [4] 85 C0 0F 84 }
        $a1 = { 39 7D B0 75 ?? 48 8D 95 18 04 00 00 48 8D 8D 60 07 00 00 E8 [4] 48 8B C8 E8 }
    condition:
        all of them
}