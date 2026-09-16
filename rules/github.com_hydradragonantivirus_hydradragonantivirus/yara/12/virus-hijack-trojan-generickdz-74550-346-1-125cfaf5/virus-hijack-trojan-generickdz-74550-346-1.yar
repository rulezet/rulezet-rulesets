rule Virus_Hijack_Trojan_GenericKDZ_74550_346_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_346_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b566d05ba2d972cf92f7cb19cec4d39ac6c8f1755a7b59d56cdb1dea3ab84506"

  strings:
    $s1 = "CRaW'[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}