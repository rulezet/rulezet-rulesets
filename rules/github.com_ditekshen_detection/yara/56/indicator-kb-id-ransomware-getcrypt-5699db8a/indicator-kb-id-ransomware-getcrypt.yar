rule INDICATOR_KB_ID_Ransomware_GetCrypt {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with GetCrypt ransomware"
    strings:
        $s1 = "getcrypt@cock.li" nocase ascii wide
        $s2 = "cryptget@tutanota.com" nocase ascii wide
        $s3 = "cryptget@tutanota.com" nocase ascii wide
        $s4 = "offtitan@pm.me" nocase ascii wide
        $s5 = "offtitan@cock.li" nocase ascii wide
        $s6 = "un42@protonmail.com" nocase ascii wide
    condition:
        any of them
}