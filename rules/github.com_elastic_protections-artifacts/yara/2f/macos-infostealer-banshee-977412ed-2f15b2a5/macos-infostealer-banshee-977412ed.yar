rule Macos_Infostealer_Banshee_977412ed {
    meta:
        author = "Elastic Security"
        id = "977412ed-4f10-4634-94e9-074629cd2c94"
        fingerprint = "dc49e9e9392ff2b8202df6f011b4494671d8a88c7efbef171b68394709d5706b"
        creation_date = "2025-02-28"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "082579d348d64cece46a726072ed87f4839f44b8a90d415c2383fcdd7566be9f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $binary_0 = { 48 89 C8 48 29 D0 48 D1 E8 48 01 D0 48 C1 E8 02 48 8D 14 C5 00 00 00 00 48 29 D0 48 01 C8 41 8A 04 07 43 88 04 26 }
        $binary_1 = { 48 C7 C2 FF FF FF FF 88 0C 10 41 8A 4C 16 02 48 FF C2 84 C9 75 }
        $binary_2 = { 88 14 31 8A 54 30 02 48 FF C6 84 D2 75 }
        $arm_binary_0 = { 08 7C 40 93 09 7D D6 9B 08 01 09 CB 28 05 48 8B 08 FD 42 D3 08 0D 08 CB 08 C1 20 8B A8 6A 68 38 E8 16 00 38 18 07 00 F1 }
    condition:
        ($binary_0 and $binary_2) or ($binary_1 and $binary_2) or $arm_binary_0
}