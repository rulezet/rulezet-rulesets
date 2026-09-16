rule Trojan_Danger_Trojan_GenericKD_72677122_186_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b9e4ba2eef3e4b281fbf8b663dd50253312812022b5a6aa41dcd11c15aeb0cd"

  strings:
    $s1 = "GolfUpdate, Version 1.0" fullword wide
    $s2 = "About GolfUpdate" fullword wide
    $s3 = "pl]Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}