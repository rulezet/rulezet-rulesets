rule INDICATOR_KB_ID_Ransomware_LockDown {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with LockDown / cantopen ransomware"
    strings:
        $s1 = "CCWhite@onionmail.org" ascii wide nocase
        $s2 = "bc1q6ug0vrxz66d564qznclu9yyyvn6zurskezmt64" ascii wide
    condition:
        any of them
}