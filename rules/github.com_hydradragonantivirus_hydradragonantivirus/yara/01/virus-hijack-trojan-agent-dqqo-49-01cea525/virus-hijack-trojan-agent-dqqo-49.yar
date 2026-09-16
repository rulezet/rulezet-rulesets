rule Virus_Hijack_Trojan_Agent_DQQO_49 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ae0001eef739ae0f19e8d578af92ed89cf42a226f3afa4751f9b021b6dc83a2"

  strings:
    $s1 = "Jprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Jprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}