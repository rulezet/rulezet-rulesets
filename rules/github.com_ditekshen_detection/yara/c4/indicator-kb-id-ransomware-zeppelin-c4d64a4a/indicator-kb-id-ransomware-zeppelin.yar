rule INDICATOR_KB_ID_Ransomware_Zeppelin {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Zeppelin ransomware"
    strings:
        $s1 = "kd8eby0@inboxhub.net" ascii wide nocase
        $s2 = "kd8eby0@onionmail.org" ascii wide nocase
        $s3 = "kd8eby0@nuke.africa" ascii wide nocase
        $s4 = "uspex1@cock.li" ascii wide nocase
        $s5 = "uspex2@cock.li" ascii wide nocase
        $s6 = "China.Helper@aol.com" ascii wide nocase
    condition:
        any of them
}