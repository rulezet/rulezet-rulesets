rule CISA_251217_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251217"
        date = "2025-12-10"
        last_modified = "20251216_729"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Rust BRICKSTORM backdoor samples"
        sha256_1 = "6a67a9769a55ec889a5dd4199b2fc08965d39d737838836853bc13c81c56a800"
        sha256_2 = "ed907d39efd5750236b075ca9fbb1f090d7bf578578c38faab24210d298a60ae" 
        sha256_3 = "0e92009fc6519c837982b3fbfd42946e827de47b73a264d693739168533d07f4"
        sha256_4 = "fb22eea57e00b83edad50ee6e02320377efc10586584c476d5018dbba3643c32"
        sha256_5 = "28a16e782f04d9394b5dfa3363d41d9f5eecc206166aeffd73363d83734a026d"
        strings:
        $s0 = { 20 55 70 67 72 61 64 65 3A 20 77 65 62 73 6F 63 6B 65 74 43 6F 6E 6E 65 63 74 69 6F 6E 3A }
        $s1 = { 20 55 70 67 72 61 64 65 53 65 63 2D 57 65 62 73 6F 63 6B 65 74 2D 4B 65 79 3A }
        $s2 = { 20 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 56 65 72 73 69 6F 6E 3A }
        $s3 = { 57 65 62 53 6F 63 6B 65 74 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 41 63 63 65 70 74 3A }
        $s4 = { 53 77 69 74 63 68 69 6E 67 20 50 72 6F 74 6F 63 6F 6C 73 }
        $s5 = { 32 35 38 45 41 46 41 35 2D 45 39 31 34 2D 34 37 44 41 2D 39 35 43 41 2D 43 35 41 42 30 44 43 38 35 42 31 31 }
        $s6 = { 2F 64 65 76 2F 70 74 6D 78 64 6F 20 66 6F 72 6B 6F 70 65 6E 20 }
        $s7 = { 53 6F 63 6B 73 35 20 63 6D 64 20 6E 6F 74 20 73 75 70 70 6F 72 74 }
        $s8 = { 62 39 32 37 35 38 61 39 61 65 66 31 63 65 66 37 62 37 39 65 32 62 37 32 63 33 64 38 62 61 31 31 33 65 35 34 37 66 38 39 }
        $s9 = { 58 34 34 38 52 69 6E 67 47 45 54 20 0D 0A 0D 0A 70 69 70 65 50 69 6E 67 50 6F 6E 67 44 61 74 61 }
    condition:
        9 of them
}