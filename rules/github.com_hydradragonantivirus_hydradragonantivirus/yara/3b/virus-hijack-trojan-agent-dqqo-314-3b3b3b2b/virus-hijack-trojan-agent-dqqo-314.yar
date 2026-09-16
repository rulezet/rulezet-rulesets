rule Virus_Hijack_Trojan_Agent_DQQO_314 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_314.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a7851b5c36a318b714139facafc41f78221aa1c0f769e63b5a4dfb34f1d592f"

  strings:
    $s1 = "LAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}