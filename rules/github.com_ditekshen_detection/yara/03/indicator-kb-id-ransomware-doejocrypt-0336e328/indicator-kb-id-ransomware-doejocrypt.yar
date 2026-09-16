rule INDICATOR_KB_ID_Ransomware_DoejoCrypt {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with DoejoCrypt ransomware"
    strings:
        $s1 = "konedieyp@airmail.cc" ascii wide nocase
        $s2 = "uenwonken@memail.com" ascii wide nocase
    condition:
        any of them
}