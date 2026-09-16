rule INDICATOR_KB_ID_Ransomware_Thanos {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Thanos ransomware"
    strings:
        $s1 = "my-contact-email@protonmail.com" ascii wide nocase
        $s2 = "get-my-data@protonmail.com" ascii wide nocase
    condition:
        any of them
}