rule Trojan_Danger_Trojan_GenericKD_72853156_486_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_486_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1fdcaef085f16ce4bb849936d45ba2222c6698e2fd08827148983f1c164b4c8"

  strings:
    $s1 = "t+ IntegratX with SOAQY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}