rule INDICATOR_KB_ID_Ransomware_Buran {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Buran ransomware"
    strings:
        $s1 = "recovery_server@protonmail.com" ascii wide nocase
        $s2 = "recovery1server@cock.li" ascii wide nocase
        $s3 = "polssh1@protonmail.com" ascii wide nocase
        $s4 = "polssh@protonmail.com" ascii wide nocase
        $s5 = "buransupport@exploit.im" ascii wide nocase
        $s6 = "buransupport@xmpp.jp" ascii wide nocase
        $s7 = "jacksteam2018@protonmail.com" ascii wide nocase
        $s8 = "notesteam2018@tutanota.com" ascii wide nocase
    condition:
        any of them
}