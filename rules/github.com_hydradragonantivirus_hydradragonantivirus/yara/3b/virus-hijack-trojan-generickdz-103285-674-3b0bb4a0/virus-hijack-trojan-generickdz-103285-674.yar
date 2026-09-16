rule Virus_Hijack_Trojan_GenericKDZ_103285_674 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_674.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33c5f7b03148b2c6e0f570e98d329ddbbf642e77c584b4834212ce60b2db8bba"

  strings:
    $s1 = "\"What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}