rule CISA_251155_01 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
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
        sha256_1 = "2bf9bfa1f9bcbcad0eada7e3be8d380d809248f08609f6e9d971b37ce09f7e93"
        sha256_2 = "6d42e9a0757670b9837034b5202d1673093577757b44bb0f0253f366413393e9"
        sha256_3 = "b30041b986ee3231fd53522c9d0c57e4567d6c60959fa06c125dde2af558fc9f"
    strings:
        $s0 = { 88 14 08 48 FF C1 }
        $s1 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 }
        $s2 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 2E 32 }
        $s3 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 }
        $s4 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 2E 66 75 6E 63 31 }
        $s5 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 }
        $s6 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 2E 66 75 6E 63 31 }
        $s7 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 63 6F 6D 6D 61 6E 64 2E 43 6F 6D 6D 61 6E 64 }
        $s8 = { 6C 69 62 73 2F 64 6F 68 2E 51 75 65 72 79 }
        $s9 = { 2F 76 65 6E 64 6F 72 2F 68 61 73 68 69 63 6F 72 70 2F 79 61 6D 75 78 2E 53 65 72 76 65 72 }
    condition:
        3 of them
}