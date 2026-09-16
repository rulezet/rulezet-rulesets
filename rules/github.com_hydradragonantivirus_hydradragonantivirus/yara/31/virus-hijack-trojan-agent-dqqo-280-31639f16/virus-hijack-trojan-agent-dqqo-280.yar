rule Virus_Hijack_Trojan_Agent_DQQO_280 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_280.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf788228190b28f04a59e63adad4aaa83fd015c8595efa426e992be9109342cb"

  strings:
    $s1 = "0eAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}