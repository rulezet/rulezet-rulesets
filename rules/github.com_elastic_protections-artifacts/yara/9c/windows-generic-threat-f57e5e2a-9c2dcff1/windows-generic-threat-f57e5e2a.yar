rule Windows_Generic_Threat_f57e5e2a {
    meta:
        author = "Elastic Security"
        id = "f57e5e2a-9a40-4131-9ed6-f9dbc88b47cf"
        fingerprint = "6066662bd5370557e8f965a3d08ff4bfb97dd78b1fd4a06b78be4b30ba976243"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bff5112830cc3547c206fb1d028c592a11a3c7cd457ef445b765af86a1e76001"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 56 57 8B 75 08 8B 4D 0C E8 00 00 00 00 58 83 C0 2A 83 EC 08 89 E2 C7 42 04 33 00 00 00 89 02 E8 0E 00 00 00 66 8C D9 8E D1 83 C4 14 5F 5E 5D C2 08 00 8B 3C 24 FF 2A 48 31 C0 57 FF D6 }
    condition:
        all of them
}