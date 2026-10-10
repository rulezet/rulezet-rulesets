rule Windows_Trojan_Kremlin_dd4e05d3 {
    meta:
        author = "Elastic Security"
        id = "dd4e05d3-e8a6-419b-894f-d66e8976b5f4"
        fingerprint = "00bab956d7afad787e0c90997bfa0e4d39356c388501ece40814baa03f6576ea"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "17c60e17d75348b055687d1ad4f66c8b12f593f68952b6de5ab181c2b7905a6c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 83 7C 24 38 00 74 ?? 83 7C 24 38 02 74 ?? 44 8B 4C 24 38 }
        $a1 = { 85 FF 74 27 83 FF 02 74 22 44 8B CF }
        $a2 = { 83 7C 24 50 00 0F 84 [4] 83 BC 24 18 48 00 00 00 0F 85 }
        $a3 = { 81 7C 24 74 90 00 00 00 0F 8C }
        $a4 = { 8B 00 89 44 24 6C 81 7C 24 6C 90 00 00 00 0F 8C }
        $b0 = "[BROWSER] Failed to extract to file"
        $b1 = "[BROWSER] Failed to init Miniz"
    condition:
        3 of them
}