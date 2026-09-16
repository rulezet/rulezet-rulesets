rule INDICATOR_KB_ID_Ransomware_Cuba {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with JobCryptor ransomware"
    strings:
        $s1 = "helpadmin2@protonmail.com" ascii wide nocase
        $s2 = "helpadmin2@cock.li" ascii wide nocase
        $s3 = "mfra@cock.li" ascii wide nocase
        $s4 = "admin@cuba-supp.com" ascii wide nocase
        $s5 = "cuba_support@exploit.im" ascii wide nocase
    condition:
        any of them
}