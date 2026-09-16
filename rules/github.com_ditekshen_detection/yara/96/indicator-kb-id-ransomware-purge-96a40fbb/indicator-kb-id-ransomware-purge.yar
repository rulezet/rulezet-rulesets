rule INDICATOR_KB_ID_Ransomware_Purge {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Purge ransomware"
    strings:
        $s1 = "rscl@dr.com" ascii wide nocase
        $s2 = "rscl@usa.com" ascii wide nocase
    condition:
        any of them
}