rule INDICATOR_KB_ID_Ransomware_AlKhal {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with AlKhal ransomware"
    strings:
        $s1 = "alkhal@tutanota.com" ascii wide nocase
        $s2 = "cyrilga@tutanota.com" ascii wide nocase
    condition:
        any of them
}