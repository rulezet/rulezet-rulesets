rule Virus_Hijack_Trojan_GenericKDZ_103545_35 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8de7dbae6b6605acd8419007fe5206915fc9d5b9184de068507d35bad1acd23c"

  strings:
    $s1 = "Psoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}