rule Virus_Hijack_Trojan_GenericKDZ_103285_876_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_876_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79ba043f212d8fc7f82605bc6f4b188f2f2fd37765780aadc6cb4792cb7f9b2b"

  strings:
    $s1 = "hmProxy!= NULL" fullword ascii
    $s2 = "Can't load library from memory." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}