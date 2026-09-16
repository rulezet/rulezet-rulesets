rule INDICATOR_KB_ID_Ransomware_BlackHunt {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with BlackHunt ransomware"
    strings:
        $s1 = "onion746@onionmail.com" ascii wide nocase
        $s2 = "amike1096@gmail.com" ascii wide nocase
        $s3 = "decryptyourdata@msgsafe.io" ascii wide nocase
        $s4 = "decryptyourdata@onionmail.org" ascii wide nocase
        $s5 = "Teikobest@gmail.com" ascii wide nocase
        $s6 = "Loxoclash@gmail.com" ascii wide nocase
        $s7 = "://sdjf982lkjsdvcjlksaf2kjhlksvvnktyoiasuc92lf.onion" ascii wide nocase
    condition:
        any of them
}