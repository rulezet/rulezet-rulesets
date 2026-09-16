rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_ait5o7p_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@ait5o7p_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b96f24542d36718cd4988a0468899b3b354d7644e91f19ca7c6d7939173a7877"

  strings:
    $s1 = "Skerry" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}