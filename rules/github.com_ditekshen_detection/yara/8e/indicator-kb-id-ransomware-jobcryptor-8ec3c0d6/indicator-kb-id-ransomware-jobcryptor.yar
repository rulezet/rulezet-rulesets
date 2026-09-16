rule INDICATOR_KB_ID_Ransomware_JobCryptor {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with JobCryptor ransomware"
    strings:
        $s1 = "olaggoune235@protonmail.ch" ascii wide nocase
        $s2 = "ouardia11@tutanota.com" ascii wide nocase
        $s3 = "laggouneo11@gmail.com" ascii wide nocase
    condition:
        any of them
}