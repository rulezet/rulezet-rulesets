rule Virus_Hijack_Trojan_Agent_DQQO_216 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_216.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "207c9de22ae85d391e5447869278f009a89fbfd55d1909e2ce64bbaafbc5c983"

  strings:
    $s1 = "Uprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Uprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}