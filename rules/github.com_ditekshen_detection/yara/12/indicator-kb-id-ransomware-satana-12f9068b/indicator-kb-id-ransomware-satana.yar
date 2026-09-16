rule INDICATOR_KB_ID_Ransomware_Satana {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Satana ransomware"
    strings:
        $s1 = "adamadam@ausi.com" ascii wide nocase
        $s2 = "XsrR2he2Z8un5ysGWnJ1wveZRPRS96XEoX" ascii wide     condition:
        any of them
}