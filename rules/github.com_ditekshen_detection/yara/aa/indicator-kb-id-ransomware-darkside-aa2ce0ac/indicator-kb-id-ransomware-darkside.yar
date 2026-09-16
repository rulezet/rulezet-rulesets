rule INDICATOR_KB_ID_Ransomware_DarkSide {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with DarkSide ransomware"
        hash1 = "bafa2efff234303166d663f967037dae43701e7d63d914efc8c894b3e5be9408"
    strings:
        $s1 = "breathcojunktab1987@yahoo.com" ascii wide nocase
    condition:
        any of them
}