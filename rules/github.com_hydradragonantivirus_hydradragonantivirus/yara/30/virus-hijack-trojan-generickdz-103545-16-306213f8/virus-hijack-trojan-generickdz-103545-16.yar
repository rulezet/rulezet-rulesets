rule Virus_Hijack_Trojan_GenericKDZ_103545_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "999a666afe2c685d367dd138f4ed4233ea66e3456ce49c0d3bda5ca809899f27"

  strings:
    $s1 = "]software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}