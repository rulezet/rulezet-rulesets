rule Virus_Hijack_Trojan_GenericKDZ_74550_50_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7d4bb21677774546806b90dba6633eaeb13f354615cf6223f4b32fa95a7cf19"

  strings:
    $s1 = "U<DOwF{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}