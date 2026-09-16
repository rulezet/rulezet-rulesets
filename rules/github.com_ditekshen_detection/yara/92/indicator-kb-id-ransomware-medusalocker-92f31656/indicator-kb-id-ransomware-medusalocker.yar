rule INDICATOR_KB_ID_Ransomware_MedusaLocker {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with MedusaLocker ransomware"
    strings:
        $s1 = "ithelpnetwork@decorous.cyou" ascii wide nocase
        $s2 = "ithelpnetwork@wholeness.business" ascii wide nocase
        $s3 = "ithelpnetwork@" ascii wide nocase
    condition:
        any of them
}