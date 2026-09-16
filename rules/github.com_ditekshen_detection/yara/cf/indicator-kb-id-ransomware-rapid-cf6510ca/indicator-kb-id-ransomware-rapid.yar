rule INDICATOR_KB_ID_Ransomware_Rapid {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Rapid ransomware"
    strings:
        $s1 = "jimmyneytron@tuta.io" ascii wide nocase
    condition:
        any of them
}