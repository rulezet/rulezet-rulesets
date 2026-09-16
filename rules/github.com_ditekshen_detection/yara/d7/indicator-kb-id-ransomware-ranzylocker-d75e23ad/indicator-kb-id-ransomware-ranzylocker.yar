rule INDICATOR_KB_ID_Ransomware_RanzyLocker {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with RanzyLocker ransomware"
    strings:
        $s1 = "eviluser@tutanota.com" ascii wide nocase
        $s2 = "evilpr0ton@protonmail.com" ascii wide nocase
    condition:
        any of them
}