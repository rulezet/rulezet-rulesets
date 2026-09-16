rule Virus_Hijack_Trojan_Agent_DQQO_75 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_75.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615d9d9e33c266ac295a477de3f2ff5adaf2ea9d156a9a20c41af947ba570791"

  strings:
    $s1 = "Qorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}