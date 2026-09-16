rule Trojan_Autorun_Trojan_Agent_CCPK_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5afdcf9176d02acee175869abbb3581a6d646a172764c0fea81350ca660b6c2a"

  strings:
    $s1 = "AUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}