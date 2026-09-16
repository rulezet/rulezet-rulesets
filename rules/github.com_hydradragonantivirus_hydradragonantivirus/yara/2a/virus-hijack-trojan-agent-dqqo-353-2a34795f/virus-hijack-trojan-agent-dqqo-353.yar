rule Virus_Hijack_Trojan_Agent_DQQO_353 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_353.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6860a7c4f87da243be5ac773aac8f76e49b689f42a253c3837e7a58fbd305e5"

  strings:
    $s1 = "oAAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}