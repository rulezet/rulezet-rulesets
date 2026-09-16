rule Virus_Hijack_Trojan_GenericKDZ_99416_44 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eefd4eebbd7f7faf324d8e4a98713aa085cb3c7827f335e26b0d368a2a8f8181"

  strings:
    $s1 = "D0User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}