rule Windows_Trojan_BruteRatel_5b12cbab {
    meta:
        author = "Elastic Security"
        id = "5b12cbab-c64c-4895-a186-b940bf4a8620"
        fingerprint = "33e4c8fa032f33bec4719707d3ddcfa5103b747d9be70fa41848fdafd254c0ac"
        creation_date = "2024-02-21"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "8165798fec8294523f25aedfc6699faad0c5d75f60bc7cefcbb2fa13dbc656e3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 81 EC 00 01 00 00 31 C0 41 89 D3 48 89 E3 88 04 18 48 FF C0 48 3D 00 01 00 00 75 F2 45 31 D2 31 FF 44 89 D0 42 8A 34 13 99 41 F7 FB 48 63 D2 8A 04 11 01 F0 01 F8 0F B6 F8 0F B6 C0 8A 14 04 }
    condition:
        all of them
}