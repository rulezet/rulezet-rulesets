rule Virus_Hijack_Trojan_GenericKDZ_103285_98 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ec216791cb0d6c98482ef0391effd8b8c2555ac59960d10eff0061896c1ecba"

  strings:
    $s1 = "~What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}