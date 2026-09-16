rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6be75a5c7870fd7bff0459bc20db62a2b7d6214712d66e5c57e27a9d21899bb"

  strings:
    $s1 = "OWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}