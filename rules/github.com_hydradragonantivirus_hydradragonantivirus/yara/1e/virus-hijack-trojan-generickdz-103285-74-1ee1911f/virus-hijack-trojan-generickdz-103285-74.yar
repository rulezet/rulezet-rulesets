rule Virus_Hijack_Trojan_GenericKDZ_103285_74 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_74.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1df6ee526144950cd629c320e5864337db62277293e6fee9dbc2e5ce350f0b72"

  strings:
    $s1 = "+What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}