rule INDICATOR_KB_ID_Ransomware_Ryzerlo {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Ryzerlo / HiddenTear / RSJON ransomware"
    strings:
        $s1 = "darkjon@protonmail.com" ascii wide nocase
    condition:
        any of them
}