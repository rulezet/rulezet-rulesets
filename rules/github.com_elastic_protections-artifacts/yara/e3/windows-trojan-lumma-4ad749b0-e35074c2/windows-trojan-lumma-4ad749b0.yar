rule Windows_Trojan_Lumma_4ad749b0 {
    meta:
        author = "Elastic Security"
        id = "4ad749b0-e853-468f-b051-210ea24cb632"
        fingerprint = "55fa938331fc42c6cdcb2a048e524c752aed8cfbe9b8128e422e1e92ac04f8c9"
        creation_date = "2024-11-08"
        last_modified = "2024-11-26"
        threat_name = "Windows.Trojan.Lumma"
        reference_sample = "1f953271bc983b3a561b85083bc14a13d18b81a34855d0a6d9fe902934347f92"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 89 E5 83 E4 F8 83 EC 10 DD 45 08 DD 54 24 08 8B 4C 24 0C 89 CA C1 EA 14 81 E2 FF 07 00 00 81 FA FF 07 00 00 74 25 66 B8 FF FF 85 D2 75 31 DD 1C 24 B8 FF FF FF 7F 23 44 24 04 31 C9 0B 04 24 }
    condition:
        all of them
}