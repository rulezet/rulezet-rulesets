rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a0kuefc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9cefaf98880643689086e3d469738b1616690e829f31741f028578077f41ffb"

  strings:
    $s1 = "U\"virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}