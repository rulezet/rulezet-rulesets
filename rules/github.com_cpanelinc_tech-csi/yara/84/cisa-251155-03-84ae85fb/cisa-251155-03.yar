rule CISA_251155_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "0cba5c6d16c7b94a450c36bfbaeab79107ac10aa9548b02c42b4b6ba8cef6a51"
    strings:
        $s0 = { CE 73 63 44 0F B6 04 30 44 31 C7 48 83 FE 19 72 DA EB 53 48 C7 04 24 }
        $s1 = { 64 48 8B 0C 25 F8 FF FF FF 48 8D 44 24 E8 48 3B }
        $s2 = { 8D 44 24 5F 48 89 04 24 48 8D 05 F9 4C 12 00 48 }
        $s3 = { 8B 4C 24 20 48 89 4C 24 30 48 8D 54 24 58 48 89 }
        $s4 = { 8B 44 24 20 48 89 44 24 30 48 8B 4C 24 18 48 89 }
        $s5 = { E8 8E 6A D5 FF 48 8B 44 24 18 48 89 84 24 98 }
        $s6 = { E8 A4 69 D5 FF 48 8B 44 24 20 48 8B 4C 24 28 48 89 84 24 B0 }
        $s7 = { 48 8D 44 24 3F 48 89 44 24 08 48 C7 44 24 10 19 }
    condition:
        all of them
}