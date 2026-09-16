rule Trojan_Autorun_Trojan_Ransom_Doboc_A_12 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e1c2f9e8365859549d8a1f2bff037dc2ebca66b306b244313a54ed2677bfcf"

  strings:
    $s1 = ",YoND!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}