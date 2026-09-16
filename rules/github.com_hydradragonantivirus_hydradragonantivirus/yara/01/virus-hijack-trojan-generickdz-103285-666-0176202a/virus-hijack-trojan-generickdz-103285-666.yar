rule Virus_Hijack_Trojan_GenericKDZ_103285_666 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_666.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf7d2d7ebf784932fafeaa8f9fc4a67280197207116bf42f313bc3cab6e3a086"

  strings:
    $s1 = "6What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}