rule Windows_Generic_Threat_23ead7ed {
    meta:
        author = "Elastic Security"
        id = "23ead7ed-72d7-43d8-a840-7babf77b3a40"
        fingerprint = "14c76873b8b58c5bffd18790ae9c43170313766b55b725dc5ccd4abcf1e28d3a"
        creation_date = "2025-01-07"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0bcd82ed4ea3e12cbaabc50df612d48078604e4d0985e9a240afc24630afa4d7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 6D 01 00 00 83 EC 18 8B 44 24 1C 89 04 24 0F B6 4C 24 20 0F B6 C9 89 4C 24 04 8B 4C 24 24 89 4C 24 08 8B 4C 24 28 89 4C 24 0C 8B 4C 24 2C }
    condition:
        all of them
}