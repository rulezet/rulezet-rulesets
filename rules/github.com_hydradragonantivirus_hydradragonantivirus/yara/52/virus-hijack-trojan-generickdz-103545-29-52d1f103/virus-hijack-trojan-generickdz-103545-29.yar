rule Virus_Hijack_Trojan_GenericKDZ_103545_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e99b7147473c5c5d52fa7b83c7fb615e741abad423e059ff8ec1596b1137a3ce"

  strings:
    $s1 = "8software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}