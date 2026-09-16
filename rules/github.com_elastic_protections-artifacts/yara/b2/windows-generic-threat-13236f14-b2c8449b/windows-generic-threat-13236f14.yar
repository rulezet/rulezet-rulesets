rule Windows_Generic_Threat_13236f14 {
    meta:
        author = "Elastic Security"
        id = "13236f14-3557-4ad9-aa19-78e79b2efd4e"
        fingerprint = "8b05f1cd70c604619f0f45467da05efa7a01a9dd49cd4e3e7fc22de814489932"
        creation_date = "2024-01-08"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a46bbcce396495c513190b272d3bc43d6579a201f5e8d103628c62888a82fa8b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 83 EC 20 48 89 CB 48 89 D6 48 89 D8 48 63 40 3C 48 8D 04 03 8B 80 88 00 00 00 4C 8D 34 18 4D 33 ED 48 33 FF 41 8B 46 20 48 8D 04 18 41 8B CD 03 C9 03 C9 8B C9 8B 04 08 48 8D 04 18 48 89 C1 }
        $b1 = "Trojan.Fabookie.Gen."
    condition:
        $a1 and not $b1
}