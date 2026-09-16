rule Virus_Hijack_Trojan_GenericKDZ_103545_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f847472b37f48b8166f04b61929273a3c34a705bd3ea3eecf5b97954e644e16"

  strings:
    $s1 = "hsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}