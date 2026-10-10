rule Windows_Trojan_Kremlin_35be03d1 {
    meta:
        author = "Elastic Security"
        id = "35be03d1-b1e2-4bba-8475-2315e72058a1"
        fingerprint = "ea382a0c50a208b9db65dd345a81999f435ec02946639a4fa19afdfe5e65cff9"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "1a2e65ff3e5b00b167af07b2797719c822efbaeff6fca2fec8b0b5b9a1f33734"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { BA 90 5F 01 00 48 8B 4C 24 40 FF 15 [4] 89 44 24 3C }
        $a1 = { 0F B6 C0 85 C0 75 ?? 48 8D 8C 24 [9] 48 83 F8 02 74 }
        $a2 = { 89 44 24 68 83 7C 24 68 00 7C ?? 48 8D 8C 24 [9] 8B 8C 24 E0 02 00 00 48 3B C8 76 }
        $a3 = { BA 40 77 1B 00 B9 C0 D4 01 00 E8 }
        $a4 = { 48 81 7C 24 ?? FE 0B 00 00 76 12 E8 }
        $b0 = "[EXT] failed to download extension from remote host"
        $b1 = "[BROWSER] Extension fully extracted to '%s'"
    condition:
        3 of them
}