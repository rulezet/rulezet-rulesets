rule Virus_Hijack_Trojan_Agent_DQQO_433 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_433.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c5ecc8835d58c1c0d648bacc642c0c5bacb505ed120d74b75c0bc750e557284"

  strings:
    $s1 = "q}nAiF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}