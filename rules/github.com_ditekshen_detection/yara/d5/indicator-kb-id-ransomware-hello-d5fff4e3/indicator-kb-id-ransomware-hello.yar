rule INDICATOR_KB_ID_Ransomware_Hello {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Hello / WickrMe ransomware"
    strings:
        $s1 = "emming@tutanota.com" ascii wide nocase
        $s2 = "ampbel@protonmail.com" ascii wide nocase
        $s3 = "asauribe@tutanota.com" ascii wide nocase
        $s4 = "candietodd@tutanota.com" ascii wide nocase
        $s5 = "kellyreiff@tutanota.com" ascii wide nocase
        $s6 = "kevindeloach@protonmail.com" ascii wide nocase
        $s7 = "sheilabeasley@tutanota.com" ascii wide nocase
    condition:
        any of them
}