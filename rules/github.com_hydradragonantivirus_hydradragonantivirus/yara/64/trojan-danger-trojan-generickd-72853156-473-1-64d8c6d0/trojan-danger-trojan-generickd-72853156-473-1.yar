rule Trojan_Danger_Trojan_GenericKD_72853156_473_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_473_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d17dae6495335479dcbc82aa4992a91749199aceffd4a7d4182426ad3237e256"

  strings:
    $s1 = "Mode<%C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}