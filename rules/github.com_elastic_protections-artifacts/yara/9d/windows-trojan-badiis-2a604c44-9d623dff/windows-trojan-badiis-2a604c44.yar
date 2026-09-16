rule Windows_Trojan_BadIIS_2a604c44 {
    meta:
        author = "Elastic Security"
        id = "2a604c44-80ad-4b25-abdc-6f57074a3b37"
        fingerprint = "3568b0878dd8404aa5a99101c132b158cea015a5397a114a28fc2057258a6f24"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "1b723a5f9725b607926e925d1797f7ec9664bb308c9602002345485e18085b72"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 FF C0 80 3C 01 00 75 F7 48 8B 72 08 }
        $a2 = { 0F 11 45 D8 4C 89 75 E8 4C 89 75 F0 4D 8B EE 4C 89 75 E8 41 BC }
        $a3 = { 49 8B C7 48 C1 E8 04 4C 8D 25 [2] 02 00 46 0F B6 }
        $a5 = { 48 8B 45 C7 48 83 F8 01 72 29 48 FF }
        $a6 = { 0F B6 44 37 FF 48 2B F8 }
    condition:
        3 of them
}