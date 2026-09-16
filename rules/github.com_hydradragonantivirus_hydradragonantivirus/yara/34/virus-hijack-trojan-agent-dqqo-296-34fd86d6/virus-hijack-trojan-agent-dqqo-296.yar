rule Virus_Hijack_Trojan_Agent_DQQO_296 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_296.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4964250856674d60f53bced7d639e160b69c93a0ecc4d3e9b80c83f43f71258"

  strings:
    $s1 = ">7Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}