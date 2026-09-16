rule mimikatz_decryptkeysign {
    strings:
        $s1 = { F6 C2 07 0F 85 0D 1A 02 00 }
        $s2 = { F6 C2 07 0F 85 72 EA 01 00 }
        $s3 = { 4C 8B CB 48 89 44 24 30}
        $s4 = { 4c 89 1b 48 89 43 08 49 89 5b 08 48 8d }

    condition:
        3 of them
}