rule Virus_Hijack_Trojan_Agent_DQQO_292 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_292.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c46160caf4b03704f9cbeb81419b10a7b23bdee2d9e639333b58c9cb1197158"

  strings:
    $s1 = "z{WinY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}