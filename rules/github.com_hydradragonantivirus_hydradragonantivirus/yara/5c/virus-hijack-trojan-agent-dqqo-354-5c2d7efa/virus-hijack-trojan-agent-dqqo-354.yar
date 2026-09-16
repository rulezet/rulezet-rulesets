rule Virus_Hijack_Trojan_Agent_DQQO_354 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_354.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ed1368a46451b8aa23778ac2e2640bd03ae195d8ae576d781c78d2b56689bae"

  strings:
    $s1 = ">orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}