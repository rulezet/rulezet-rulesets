rule Virus_Hijack_Trojan_Agent_DQQO_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c0927b185ddbe07115f6bd13be72dd439022f09b359c47aad5192ed0cce259"

  strings:
    $s1 = "Copyright (C) 2008-2009,Stepok Image Lab." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}