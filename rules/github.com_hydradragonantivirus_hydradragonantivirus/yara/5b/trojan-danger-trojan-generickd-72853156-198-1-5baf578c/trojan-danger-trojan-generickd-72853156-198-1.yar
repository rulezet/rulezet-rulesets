rule Trojan_Danger_Trojan_GenericKD_72853156_198_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_198_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4c6d76e36aa3cda944e1dda2e2eea5baa1cc8ad60ab7b2a64b907ba7f09b6f1"

  strings:
    $s1 = "*,Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}