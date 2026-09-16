rule INDICATOR_KB_ID_Ransomware_Payola {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Payola ransomware"
    strings:
        $s1 = "pcsupport@skiff.com" ascii wide nocase
        $s2 = "pctalk01@tutanota.com" ascii wide nocase
    condition:
        any of them
}