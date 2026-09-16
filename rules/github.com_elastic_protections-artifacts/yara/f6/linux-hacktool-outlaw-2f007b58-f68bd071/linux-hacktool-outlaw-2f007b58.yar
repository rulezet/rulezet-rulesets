rule Linux_Hacktool_Outlaw_2f007b58 {
    meta:
        author = "Elastic Security"
        id = "2f007b58-2041-4ef8-8bd5-3a76a6e86ece"
        fingerprint = "7fc8a66712a147a1006e053b9e957b4e6029a793850e187ec8e1c4921f454462"
        creation_date = "2025-02-28"
        last_modified = "2025-03-07"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $x64_start_thread = { 31 DB B9 10 00 00 00 4C 8B 44 24 10 48 89 D8 48 89 EF BE 7F 00 00 00 F3 48 AB 48 8B 4C 24 08 }
        $x64_main = { 4B 8B 04 F7 48 89 42 10 4B 8B 44 F7 10 48 89 42 18 4B 8B 44 F7 20 48 89 42 20 4B 8B 44 F7 08 48 89 42 28 4B 8B 44 F7 18 48 89 42 30 4B 8B 44 F7 28 48 89 42 38 4D 85 F6 74 7B }
        $x64_main_getopt = { 4C 89 EE 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 11 83 E8 48 83 F8 2E 77 E2 49 63 04 84 4C 01 E0 FF E0 }
        $x64_ip_select = { 89 C2 48 98 48 69 C0 AB AA AA 2A 89 D1 C1 F9 1F 48 C1 E8 20 29 C8 8D 0C 40 89 D0 01 C9 29 C8 83 F8 02 }
        $x86_main = { 83 C4 10 C6 04 06 00 8B 85 00 C2 FC FF 89 34 B8 83 C7 01 8B 85 10 C2 FC FF 83 EC 08 01 F8 89 85 04 C2 FC FF 89 85 0C C2 FC FF FF B5 08 C2 FC FF 6A 00 }
        $x86_main_getopt = { 83 C4 10 83 F8 FF 74 13 83 E8 48 83 F8 2E 8B 8C 83 ?? ?? ?? ?? 01 D9 FF E1 }
        $x86_ip_select = { BA AB AA AA 2A 83 C4 10 89 C1 F7 EA 89 C8 C1 F8 1F 29 C2 8D 04 52 01 C0 29 C1 83 F9 02 }
        $x86_worker = { 83 C4 10 8D 7C 24 10 90 8B 46 04 85 C0 74 4F 8B 6E 74 83 EC 0C 55 }
    condition:
        3 of ($x64*) or 3 of ($x86*)
}