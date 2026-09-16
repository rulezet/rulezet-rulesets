rule Windows_Generic_Threat_3055c14a {
    meta:
        author = "Elastic Security"
        id = "3055c14a-3c32-4f42-8ea0-4a6add8174bc"
        fingerprint = "de7955235c4dac09ef5ae7228ef5cc8205c17e441132e77dee3697629d9824f0"
        creation_date = "2025-01-09"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "69e0e00babc6365144a98c2866353ef973b7dfe69ae37068f807d4b12c017161"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC E0 00 00 00 48 8B F1 ?? ?? ?? ?? ?? ?? 48 63 F8 85 C0 75 11 48 8B B4 24 F8 00 00 00 48 81 C4 E0 00 00 00 5F C3 8D 47 01 48 89 9C 24 F0 00 00 00 48 63 C8 B8 02 00 00 00 48 F7 E1 }
    condition:
        all of them
}