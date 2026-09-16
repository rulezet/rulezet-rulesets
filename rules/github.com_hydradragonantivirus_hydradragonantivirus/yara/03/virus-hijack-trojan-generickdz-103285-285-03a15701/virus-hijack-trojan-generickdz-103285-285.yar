rule Virus_Hijack_Trojan_GenericKDZ_103285_285 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_285.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abd2954037cad4816941fc8d87db7fc00108245b89061698574415f04da1c1bf"

  strings:
    $s1 = "D@OxEn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}