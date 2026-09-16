rule Virus_Hijack_Trojan_GenericKDZ_98388_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3cc4cc06e97cf8b2aaac2183ace1f4004d14264c9e564bf2fec20806b7ad342"

  strings:
    $s1 = "Rime!;Zo" fullword ascii
    $s2 = "$;haTH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}