rule Virus_Hijack_Trojan_GenericKDZ_105924_315_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_315_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15b4cc89290bef3b544ea291222618a351fac7d6393065027f3e6b2efddea3ee"

  strings:
    $s1 = "SLiD]G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}