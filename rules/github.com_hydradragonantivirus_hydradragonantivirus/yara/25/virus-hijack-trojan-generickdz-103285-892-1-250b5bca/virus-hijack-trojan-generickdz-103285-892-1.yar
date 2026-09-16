rule Virus_Hijack_Trojan_GenericKDZ_103285_892_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_892_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3bc3fd621dc2d86fbd421c7086d4f5933a39f989741d07c20fc86fa597185da"

  strings:
    $s1 = "o:FLIP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}