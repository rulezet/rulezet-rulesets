rule INDICATOR_KB_ID_Ransomware_AlumniLocker {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with AlumniLocker ransomware"
    strings:
        $s1 = "alumnilocker@protonmail.com" ascii wide nocase
    condition:
        any of them
}