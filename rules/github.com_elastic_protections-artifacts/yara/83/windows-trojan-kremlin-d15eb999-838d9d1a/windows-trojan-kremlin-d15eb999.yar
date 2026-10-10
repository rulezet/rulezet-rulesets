rule Windows_Trojan_Kremlin_d15eb999 {
    meta:
        author = "Elastic Security"
        id = "d15eb999-819a-4315-b51b-e1bbe1dfb873"
        fingerprint = "3d81db124feed487d5cec23e01317e56d6268659b7616d0a4569bee3250d54e2"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "8f7d67c51cf8388b6e01526984952fb58bad47dd511d02bf7f73cd4846f84274"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { BA 90 5F 01 00 48 8B C8 FF 15 [4] 44 89 75 C7 85 C0 }
        $a1 = { 48 8B 94 24 [4] 48 2B 94 24 [4] 48 83 C2 1F }
        $a2 = { B8 40 77 1B 00 48 2B C6 48 3B C1 48 0F 42 C8 }
        $a3 = { 48 3D FE 0B 00 00 76 12 E8 }
        $b0 = "[EXT] failed to calculate extension id"
        $b1 = "[BROWSER] Extracting ext into %s"
    condition:
        4 of them
}