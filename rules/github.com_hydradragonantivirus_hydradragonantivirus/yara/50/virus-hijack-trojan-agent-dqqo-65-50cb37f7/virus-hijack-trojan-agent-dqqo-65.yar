rule Virus_Hijack_Trojan_Agent_DQQO_65 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_65.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bfd939a7362eebdda7634873c968fab67c055eed68ae97baec119069ce1e2ae"

  strings:
    $s1 = "Worders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}