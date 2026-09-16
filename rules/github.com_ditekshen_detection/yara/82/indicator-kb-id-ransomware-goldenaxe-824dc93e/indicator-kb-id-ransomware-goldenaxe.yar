rule INDICATOR_KB_ID_Ransomware_GoldenAxe {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with GoldenAxe ransomware"
    strings:
        $s1 = "xxback@keemail.me" nocase ascii wide
        $s2 = "darkusmbackup@protonmail.com" nocase ascii wide
    condition:
        any of them
}