rule INDICATOR_KB_ID_Ransomware_RansomwareEXX {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with RansomwareEXX Linux ransomware"
    strings:
        $s1 = "france.eigs@protonmail.com" ascii wide nocase
    condition:
        any of them
}