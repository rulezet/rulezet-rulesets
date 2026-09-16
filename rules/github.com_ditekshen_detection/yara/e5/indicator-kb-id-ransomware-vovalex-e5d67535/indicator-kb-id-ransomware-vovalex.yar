rule INDICATOR_KB_ID_Ransomware_Vovalex {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Vovalex ransomware"
    strings:
        $s1 = "vovanandlexus@cock.li" ascii wide nocase
    condition:
        any of them
}