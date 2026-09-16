rule Virus_Danger_Trojan_Agent_DQQO_16 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f83cb6a67fe6b1e98d2e5cfe0c3610dc8b79596e6d6a48450f0865ae1babc6e"

  strings:
    $s1 = "rAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}