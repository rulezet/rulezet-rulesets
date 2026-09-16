rule Virus_Hijack_Trojan_Agent_DQQO_418 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_418.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fc1346697c01e2f0e429a1602b9a7ad5376886432b19713bd8a8cc03180dd6d"

  strings:
    $s1 = "TOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}