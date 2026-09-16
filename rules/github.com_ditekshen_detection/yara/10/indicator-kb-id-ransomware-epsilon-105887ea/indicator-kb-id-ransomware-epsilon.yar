rule INDICATOR_KB_ID_Ransomware_Epsilon {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Epsilon ransomware"
    strings:
        $s1 = "neftet@tutanota.com" ascii wide nocase
    condition:
        any of them
}