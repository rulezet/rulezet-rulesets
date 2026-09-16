rule Virus_Hijack_Trojan_GenericKDZ_103545_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7e27566550696817d2cca7c68e2adbeb870c637a8c93f9672875601f808a4d2"

  strings:
    $s1 = ":software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}