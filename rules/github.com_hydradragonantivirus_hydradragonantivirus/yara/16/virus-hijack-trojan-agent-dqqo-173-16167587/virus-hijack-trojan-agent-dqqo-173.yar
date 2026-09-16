rule Virus_Hijack_Trojan_Agent_DQQO_173 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_173.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c563215cbf7a5f3b26aafd0c7d2d20604cbb57f0e0db46fe44904fb741c3f239"

  strings:
    $s1 = "%gIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}