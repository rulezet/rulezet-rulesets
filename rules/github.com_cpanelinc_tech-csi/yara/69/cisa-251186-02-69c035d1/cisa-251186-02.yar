rule CISA_251186_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251186"
        date = "2025-11-17"
        last_modified = "n/a"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "57bd98dbb5a00e54f07ffacda1fea91451a0c0b532cd7d570e98ce2ff741c21d"
    strings:
        $s0 = { 31 F7 40 88 7C 04 4C 48 FF C0 }
        $s1 = { 44 01 C7 40 88 7C 14 30 48 FF C2 0F 1F 00 }
        $s2 = { 41 89 F0 31 FE 01 D6 66 90 49 83 F8 11 }
        $s3 = { 48 8B 44 24 08 48 8B 5C 24 10 48 8B 4C 24 18 }
        $s4 = { 48 89 C1 48 89 DF 48 8D 05 0F 6F 15 00}
        $s5 = { 48 8D 3D 9A 6D 15 00 4D 89 C1 49 89 F0 }
        $s6 = { 81 39 49 43 4D 50 74 0C }
        $s7 = { E8 FB E6 FF FF E8 76 D0 FF FF E8 91 C0 FF FF 48 8B 05 EA BF 53 }
    condition:
        all of them
}