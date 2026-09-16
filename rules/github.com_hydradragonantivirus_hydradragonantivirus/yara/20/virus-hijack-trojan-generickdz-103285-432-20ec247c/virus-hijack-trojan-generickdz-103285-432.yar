rule Virus_Hijack_Trojan_GenericKDZ_103285_432 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_432.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3325aabbdf2a990915a9dd21d7f752e20bc11ef970beddae37e2d7b907426324"

  strings:
    $s1 = "MWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}