rule INDICATOR_KB_ID_Ransomware_LokiLocker {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with LokiLocker ransomware"
    strings:
        $s1 = "Unlockpls.dr01@yahoo.com" ascii wide nocase
    condition:
        any of them
}