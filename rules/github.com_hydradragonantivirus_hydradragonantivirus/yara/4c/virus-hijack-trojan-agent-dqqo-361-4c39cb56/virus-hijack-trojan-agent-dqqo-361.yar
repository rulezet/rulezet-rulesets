rule Virus_Hijack_Trojan_Agent_DQQO_361 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_361.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34d986563f6105a2218f94df3b081168cda242537dcd1ed1d298bf7c9237adae"

  strings:
    $s1 = "gorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}