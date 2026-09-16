rule Windows_Generic_Threat_491a8310 {
    meta:
        author = "Elastic Security"
        id = "491a8310-f42f-4069-a2ab-d65172055ba1"
        fingerprint = "5e4ec33a39f44925af4c7f743a04ae38f13cb3cbc6a0e55e9fcd777a1abd3122"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "59c6846b4676378d9c80d7ced825f0463d1b333546bfcad919ee262cbf6db250"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 8B 45 0C 83 E8 02 74 21 2D 10 01 00 00 75 23 8B 45 14 50 8B 45 10 50 8B 45 0C 50 8B 45 08 50 ?? ?? ?? ?? ?? 89 45 FC EB 28 6A 00 ?? ?? ?? ?? ?? EB 1A 8B 45 14 50 8B 45 10 50 }
    condition:
        all of them
}