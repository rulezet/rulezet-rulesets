rule INDICATOR_KB_ID_Ransomware_LockerGoga {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with LockerGoga ransomware"
    strings:
        $s1 = "abbschevis@protonmail.com" nocase ascii wide
        $s2 = "aperywsqaroci@o2.pl" nocase ascii wide
        $s3 = "asuxidoruraep1999@o2.pl" nocase ascii wide
        $s4 = "dharmaparrack@protonmail.com" nocase ascii wide
        $s5 = "ijuqodisunovib98@o2.pl" nocase ascii wide
        $s6 = "mayarchenot@protonmail.com" nocase ascii wide
        $s7 = "mikllimiteds@gmail.com0" nocase ascii wide
        $s8 = "phanthavongsaneveyah@protonmail.com" nocase ascii wide
        $s9 = "qicifomuejijika@o2.pl" nocase ascii wide
        $s10 = "rezawyreedipi1998@o2.pl" nocase ascii wide
        $s11 = "sayanwalsworth96@protonmail.com" nocase ascii wide
        $s12 = "suzumcpherson@protonmail.com" nocase ascii wide
        $s13 = "wyattpettigrew8922555@mail.com" nocase ascii wide
    condition:
        any of them
}