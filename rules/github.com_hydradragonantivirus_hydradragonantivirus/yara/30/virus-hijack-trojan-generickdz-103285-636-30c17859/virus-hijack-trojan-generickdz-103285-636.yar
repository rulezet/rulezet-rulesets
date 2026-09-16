rule Virus_Hijack_Trojan_GenericKDZ_103285_636 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_636.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "899a9482e649bd35b1b7c7bb3e39e4faa456d2fed34358b05c8c0957fa1bb025"

  strings:
    $s1 = "vWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}