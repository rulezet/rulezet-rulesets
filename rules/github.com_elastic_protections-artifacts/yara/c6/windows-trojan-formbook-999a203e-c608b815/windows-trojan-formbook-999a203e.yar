rule Windows_Trojan_Formbook_999a203e {
    meta:
        author = "Elastic Security"
        id = "999a203e-70ec-4100-ab3f-23e99b00041c"
        fingerprint = "61544f5c38d3f0cca7a867c973fd1ba713a187f63b25364b51fb0290221d21a4"
        creation_date = "2025-09-09"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Formbook"
        reference_sample = "fe6b659e6a6d19470cf5cfb5dfef263d22119463a6d084c31006c24c0045bd72"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8D 44 37 FE 8D 4E FF 8A 50 01 28 10 48 49 75 ?? 83 FE 01 76 ?? 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 }
        $b = { B8 90 90 90 90 89 07 66 89 47 04 8D 5F 06 BF 04 00 00 00 39 7D FC 76 }
        $c = { B2 88 81 3C 31 40 41 49 48 75 ?? 80 7C 31 04 B8 75 ?? 38 54 31 05 }
        $d = { 8D 57 FD 52 C7 45 14 90 90 90 90 C7 45 F8 55 8B EC 00 C7 45 FC 00 00 00 00 }
    condition:
        3 of them
}