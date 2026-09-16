rule Virus_Hijack_Trojan_Agent_DQQO_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca559e4e287de1909587a92b41d91e5fe6c0ea247d25e8f39d08c477235ed41"

  strings:
    $s1 = "~Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}