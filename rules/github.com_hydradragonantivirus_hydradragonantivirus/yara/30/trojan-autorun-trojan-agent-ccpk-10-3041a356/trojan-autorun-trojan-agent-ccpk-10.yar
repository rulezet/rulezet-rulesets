rule Trojan_Autorun_Trojan_Agent_CCPK_10 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32f5779cc85b23b91c6927aeba233cdc15d4f416d1cdc5ea95e93d125b24f4ad"

  strings:
    $s1 = "z[\"A}SavE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}