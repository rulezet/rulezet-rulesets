rule Virus_Hijack_Trojan_Agent_DQQO_397 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_397.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1750802f3ef43e3c603f53fcafea2671ba836a2fc2d46ee9191c2d90b241666a"

  strings:
    $s1 = "'Awhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}