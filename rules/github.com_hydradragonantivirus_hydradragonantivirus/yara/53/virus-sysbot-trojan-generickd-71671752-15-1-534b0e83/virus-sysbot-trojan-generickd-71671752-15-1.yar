rule Virus_Sysbot_Trojan_GenericKD_71671752_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b1f7b1350607c0ae50e29297e2c1ccc4ce268fbf9e1b256d50fec473d1d082e"

  strings:
    $s1 = "tuke]R(X" fullword ascii
    $s2 = "K &FiFo" fullword ascii
    $s3 = "H<SToP" fullword ascii
    $s4 = "*sTaW " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}