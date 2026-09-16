rule Trojan_Autorun_Trojan_GenericKD_72517131_228_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e3410b519c43fa5268241dd99956fb2ce6940bcebffdba73be923bf00773020"

  strings:
    $s1 = "(User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}