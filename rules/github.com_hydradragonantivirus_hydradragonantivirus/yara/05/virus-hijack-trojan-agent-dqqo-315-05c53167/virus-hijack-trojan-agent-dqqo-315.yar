rule Virus_Hijack_Trojan_Agent_DQQO_315 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_315.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "238a9a7ff1dfe426b6dbb5710cd0909fc432a4b7e977fddec42d339f67371c52"

  strings:
    $s1 = "AIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}