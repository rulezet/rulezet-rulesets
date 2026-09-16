rule Windows_Trojan_GhostPulse_9e22c56d {
    meta:
        author = "Elastic Security"
        id = "9e22c56d-91bf-4259-8b60-aa7323b5e8f9"
        fingerprint = "5e9883ad58fee79960a6e5e3c266885c6dc72057a16f4ea0e371088571e9b663"
        creation_date = "2024-07-21"
        last_modified = "2024-07-26"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "349b4dfa1e93144b010affba926663264288a5cfcb7b305320f466b2551b93df"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C7 44 24 28 80 3C 36 FE C7 44 24 2C FF FF FF FF 53 6A 00 }
        $b = { 80 7C 24 04 3F ?? ?? 8A 74 24 08 38 74 1E 05 8A 6C 24 10 ?? ?? 80 7C 24 08 3F }
        $c = { 89 41 5C 8B 44 24 ?? 8B 80 04 01 00 00 89 44 24 ?? 8B 42 3C 8B 44 02 78 8B 4C 02 20 01 D1 89 4C 24 ?? 8B 4C 02 1C 89 4C 24 ?? 8B 44 02 24 89 44 }
    condition:
        any of them
}