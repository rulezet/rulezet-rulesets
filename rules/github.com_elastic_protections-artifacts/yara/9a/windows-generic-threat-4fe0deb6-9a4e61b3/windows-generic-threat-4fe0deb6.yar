rule Windows_Generic_Threat_4fe0deb6 {
    meta:
        author = "Elastic Security"
        id = "4fe0deb6-02ed-4530-8574-bf5c8e1094f7"
        fingerprint = "2c6f78007df750d4c4cf4ec42f023ab6b5e1a2307a9b19f6c7b818106c0115d2"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5836ef66985e851b37a369b04cce579afdb3b241d46a096bf8b1e8d4df053cd2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC DD 45 08 B9 00 00 F0 7F D9 E1 B8 00 00 F0 FF 39 4D 14 75 3B 83 7D 10 00 75 75 D9 E8 D8 D1 DF E0 F6 C4 05 7A 0F DD D9 DD D8 DD 05 A8 B7 44 00 E9 E9 00 00 00 D8 D1 DF E0 DD D9 F6 C4 41 }
    condition:
        all of them
}