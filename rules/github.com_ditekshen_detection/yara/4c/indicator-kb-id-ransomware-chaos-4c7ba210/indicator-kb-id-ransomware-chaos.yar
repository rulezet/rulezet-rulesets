rule INDICATOR_KB_ID_Ransomware_Chaos {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Chaos ransomware"
    strings:
        $s1 = "anenomous31@gmail.com" ascii wide nocase
        $s2 = "daengsocietyteam@gmail.com" ascii wide nocase
        $s3 = "RansHelp@tutanota.com" ascii wide nocase
        $s4 = "18vhBpgPhZrjJkbuT2ZyUXAnJavaJcTwEd" ascii wide
        $s5 = "bc1qlnzcep4l4ac0ttdrq7awxev9ehu465f2vpt9x0" ascii wide
        $s6 = "8AFtPnreZp28xoetUyKiQvVtwrov9PtEbMyvczdNZpBN45EUbEsrE8xYVp4NNqPrtxNjQwn3PbW3FG16EPYcPpKzMU78xN6" ascii wide
        $s7 = "bc1qu6tharwawwny28z9fj6nrxg5cqftaep9ap6z2v" ascii wide
        $s8 = "bambolina2021@virgilio.it" ascii wide nocase
        $s9 = "1EoyuvcXdAQQvStkoJZ38vdGm84StD7wjm" ascii wide
        $s10 = "1G395PJs8ciqvXPZEYb1LfUGPix9h9n3oQ" ascii wide
            condition:
        any of them
}