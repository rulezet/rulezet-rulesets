rule INDICATOR_KB_ID_Ransomware_Rhysida {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Rhysida ransomware"
    strings:
        $s1 = "SethZemlak@onionmail.org" ascii wide nocase
        $s2 = "JacquieKunze@onionmail.org" ascii wide nocase
    condition:
        any of them
}