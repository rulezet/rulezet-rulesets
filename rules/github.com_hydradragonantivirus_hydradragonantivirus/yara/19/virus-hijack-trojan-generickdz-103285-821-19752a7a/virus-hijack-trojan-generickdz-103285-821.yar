rule Virus_Hijack_Trojan_GenericKDZ_103285_821 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_821.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43abddf473c5e1fc4ff3e764d8e066ac3d55edf3f842dbec4f28bfd5d81f429e"

  strings:
    $s1 = ":What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}