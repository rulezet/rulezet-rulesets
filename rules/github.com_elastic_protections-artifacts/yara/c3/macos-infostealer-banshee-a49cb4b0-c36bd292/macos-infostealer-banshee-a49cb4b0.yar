rule Macos_Infostealer_Banshee_a49cb4b0 {
    meta:
        author = "Elastic Security"
        id = "a49cb4b0-8c14-439d-9306-db76a421344f"
        fingerprint = "46d147ebb42fd356318d380f82160ecd6ba29efd3f62b846bd945837458d54b5"
        creation_date = "2025-12-30"
        last_modified = "2026-04-06"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "00c68fb8bcb44581f15cb4f888b4dec8cd6d528cacb287dc1bdeeb34299b8c93"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $x64_a = { 49 89 F0 49 D3 E8 44 30 07 48 83 C2 08 48 FF C7 }
        $x64_b = { 88 14 08 8A 54 31 02 48 FF C1 48 83 F9 }
        $arm_a = { 2B 25 CB 9A 4C 01 40 39 8B 01 0B 4A 4B 15 00 38 08 21 00 91 }
        $arm_b = { 0A 69 29 38 8A 05 40 39 29 05 00 91 }
    condition:
        all of ($x64_*) or all of ($arm_*)
}