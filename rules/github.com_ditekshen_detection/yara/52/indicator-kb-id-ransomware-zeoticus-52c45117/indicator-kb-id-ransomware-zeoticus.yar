rule INDICATOR_KB_ID_Ransomware_Zeoticus {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Zeoticus ransomware"
    strings:
        $s1 = "anobtanium@tutanota.com" ascii wide nocase
        $s2 = "anobtanium@cock.li" ascii wide nocase
    condition:
        any of them
}