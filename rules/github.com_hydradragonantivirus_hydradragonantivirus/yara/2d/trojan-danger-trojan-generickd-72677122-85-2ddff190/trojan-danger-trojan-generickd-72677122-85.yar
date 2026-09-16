rule Trojan_Danger_Trojan_GenericKD_72677122_85 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_85.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaa2ad0cbca0aef068ed47c25348f31e201e873a7a4200dc38720dd324dea4e3"

  strings:
    $s1 = " ;tEEn" fullword ascii
    $s2 = "ripe'0" fullword ascii
    $s3 = "GYPS(+" fullword ascii
    $s4 = "*WArK." fullword ascii
    $s5 = "+#More" fullword ascii
    $s6 = "S%Gash" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}