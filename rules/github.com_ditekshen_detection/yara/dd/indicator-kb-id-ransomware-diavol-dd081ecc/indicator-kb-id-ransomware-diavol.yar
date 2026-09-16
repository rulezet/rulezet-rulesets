rule INDICATOR_KB_ID_Ransomware_Diavol {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Diavol ransomware"
    strings:
        $s1 = "/noino.5fws6uqv5byttg2r//:sptth" ascii wide nocase
        $s2 = "https://r2gttyb5vqu6swf5.onion/" ascii wide nocase
    condition:
        any of them
}