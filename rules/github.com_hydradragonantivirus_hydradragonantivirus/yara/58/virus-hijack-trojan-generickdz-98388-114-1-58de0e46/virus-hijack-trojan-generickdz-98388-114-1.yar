rule Virus_Hijack_Trojan_GenericKDZ_98388_114_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fd05680097a772d83044255ea7552b203301e31a3ce424c1c8415e5c7cdf2c1"

  strings:
    $s1 = "RoXy(\\" fullword ascii
    $s2 = "tuft`5" fullword ascii
    $s3 = "{z>bAIn" fullword ascii
    $s4 = "?SCUn@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}