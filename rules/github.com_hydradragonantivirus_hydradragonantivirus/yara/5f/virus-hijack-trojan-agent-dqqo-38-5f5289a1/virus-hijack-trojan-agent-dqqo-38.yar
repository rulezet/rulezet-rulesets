rule Virus_Hijack_Trojan_Agent_DQQO_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dc7cd2ad27b12cb7cb2987a638939cd2d7728824ff7b7e664d22e6fcab04783"

  strings:
    $s1 = "PIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}