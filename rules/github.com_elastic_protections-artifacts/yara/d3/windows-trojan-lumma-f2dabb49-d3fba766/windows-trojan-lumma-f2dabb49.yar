rule Windows_Trojan_Lumma_f2dabb49 {
    meta:
        author = "Elastic Security"
        id = "f2dabb49-9da9-49e2-ba5a-be380f0d9c5e"
        fingerprint = "23aed246ebf9ef771450e457082e57e7868efff1ad3f94df0cc99c03005d5040"
        creation_date = "2025-08-27"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Lumma"
        reference_sample = "26803ff0e079e43c413e10d9a62d344504a134d20ad37af9fd3eaf5c54848122"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $crypto_setup_pattern = { B8 38 ?2 4? 00 B? [3] 00 B? [3] 00 96 F3 A5 }
        $decryption_function_pattern = { 55 53 57 56 81 EC 1? 01 00 00 8B ?? 24 3? 01 00 00 85 ?? 0F 84 ?? 08 00 00 }
        $c2_decryption_branch_pattern = { 8D 8? E0 ?2 4? 00 8D 74 24 ?? FF 3? 56 5? 68 ?? ?? 45 00 E8 ?? ?? FF FF }
    condition:
        2 of them
}