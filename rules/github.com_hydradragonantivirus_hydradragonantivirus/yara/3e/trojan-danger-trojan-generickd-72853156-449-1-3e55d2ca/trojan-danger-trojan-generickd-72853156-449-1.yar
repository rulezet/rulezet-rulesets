rule Trojan_Danger_Trojan_GenericKD_72853156_449_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_449_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7af2048f2ff870c75b977bc0ad8bfaad5049f1927696e00e808da6ee9448ea65"

  strings:
    $s1 = "5!GauN." fullword ascii
    $s2 = "~$BlAE(d" fullword ascii
    $s3 = ",V;Kept" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}