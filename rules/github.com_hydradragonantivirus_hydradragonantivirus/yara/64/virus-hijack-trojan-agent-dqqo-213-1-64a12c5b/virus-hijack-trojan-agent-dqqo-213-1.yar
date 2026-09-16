rule Virus_Hijack_Trojan_Agent_DQQO_213_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb6aec2fc6768a11368bfee2d49ddc1874a810c28ea5df07871db7797a3f26e"

  strings:
    $s1 = ".IEC 61966-2.1 Defaul= RGB colour space - sRGB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}