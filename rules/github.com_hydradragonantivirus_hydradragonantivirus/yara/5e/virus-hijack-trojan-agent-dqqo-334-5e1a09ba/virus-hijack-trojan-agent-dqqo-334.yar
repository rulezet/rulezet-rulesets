rule Virus_Hijack_Trojan_Agent_DQQO_334 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_334.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03588b5d7a15c6fc255363f53395aa6920f20a61eab08d0d42c397d52aa6dcb5"

  strings:
    $s1 = "WHAm%1UlbTt9LRk.JDn" fullword ascii
    $s2 = "KOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}