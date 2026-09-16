rule INDICATOR_KB_ID_Ransomware_Phobos {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Phobos ransomware"
    strings:
        $s1 = "helprecover@foxmail.com" ascii wide nocase
        $s2 = "recoverhelp2020@thesecure.biz" ascii wide nocase
    condition:
        any of them
}