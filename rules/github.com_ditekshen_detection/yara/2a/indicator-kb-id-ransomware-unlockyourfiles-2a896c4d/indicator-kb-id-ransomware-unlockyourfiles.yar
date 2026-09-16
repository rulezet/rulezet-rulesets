rule INDICATOR_KB_ID_Ransomware_UnlockYourFiles {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with UnlockYourFiles ransomware"
    strings:
        $s1 = "4lok3r@tutanota.com" ascii wide nocase
        $s2 = "4lok3r@protonmail.com" ascii wide nocase
    condition:
        any of them
}