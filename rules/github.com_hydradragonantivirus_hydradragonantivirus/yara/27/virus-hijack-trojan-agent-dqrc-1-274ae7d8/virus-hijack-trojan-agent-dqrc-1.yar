rule Virus_Hijack_Trojan_Agent_DQRC_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQRC_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "021568c127e68f6a5c467ba523582ed696d302475f9d575a318a8f8553a4bcd6"

  strings:
    $s1 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}