rule Virus_Hijack_Trojan_Agent_DQQO_278 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_278.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21af9c57ea7cf5a84ddae646dc34aedd09df48ae93b1721966de317ce778695b"

  strings:
    $s1 = "Kprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Kprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}