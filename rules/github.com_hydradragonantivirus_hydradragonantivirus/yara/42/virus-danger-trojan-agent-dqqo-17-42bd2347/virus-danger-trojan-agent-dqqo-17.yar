rule Virus_Danger_Trojan_Agent_DQQO_17 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1186426df1c95a5a9821821244749edfe66f7bf3ae79cb2dbd16ac3274450870"

  strings:
    $s1 = "dJprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "dJprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}