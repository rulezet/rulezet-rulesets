rule Virus_Hijack_Trojan_GenericKDZ_105924_292_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_292_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93e686de6ef93a3e35c906f2b69d6e0314504c73bdc8856cb1213f06faeefc20"

  strings:
    $s1 = "poUCe}" fullword ascii
    $s2 = "9l`Duit" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}