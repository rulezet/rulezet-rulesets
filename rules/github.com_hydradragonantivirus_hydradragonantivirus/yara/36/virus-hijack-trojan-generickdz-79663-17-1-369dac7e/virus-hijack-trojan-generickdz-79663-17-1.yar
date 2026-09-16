rule Virus_Hijack_Trojan_GenericKDZ_79663_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef2956b3aa76e0e68769f881bf2c9b25df3feb927a35ec0f8ed55938a866eed2"

  strings:
    $s1 = "THawN;" fullword ascii
    $s2 = "h(SLOw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}