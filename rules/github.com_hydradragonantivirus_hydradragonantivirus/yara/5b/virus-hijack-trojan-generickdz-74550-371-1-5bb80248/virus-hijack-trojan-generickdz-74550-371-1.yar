rule Virus_Hijack_Trojan_GenericKDZ_74550_371_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_371_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21ab3c01f2b88310db872bd0683bd4568d17d61f0cdedb3f73dc599b85db2313"

  strings:
    $s1 = "rUsk&N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}