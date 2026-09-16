rule INDICATOR_KB_ID_Ransomware_Spyro {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Spyro ransomware"
    strings:
        $s1 = "blackspyro@tutanota.com" ascii wide nocase
        $s2 = "blackspyro@mailfence.com" ascii wide nocase
    condition:
        any of them
}