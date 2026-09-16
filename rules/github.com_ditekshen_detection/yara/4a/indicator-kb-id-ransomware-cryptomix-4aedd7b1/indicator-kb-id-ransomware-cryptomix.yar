rule INDICATOR_KB_ID_Ransomware_CryptoMix {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with CryptoMix ransomware"
    strings:
        $s1 = "portstatrelea1982@protonmail.om" ascii wide nocase
        $s2 = "unlock@eqaltech.su" ascii wide nocase
        $s3 = "unlock@royalmail.su" ascii wide nocase
        $s4 = "adexsin276@gmail.com" ascii wide nocase
        $s5 = "nbactocepnyou@protonmail.com" ascii wide nocase
        $s6 = "nunlock@eqaltech.su" ascii wide nocase
        $s7 = "nsnlock@royalmail.su" ascii wide nocase
        $s8 = "cersiacsofal@protonmail.com" ascii wide nocase
    condition:
        any of them
}