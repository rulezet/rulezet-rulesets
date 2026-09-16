rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72b01a98e8ea86707508de97b5d1709574ea9ee9082c3204bcf7e5ffb6cc75ca"

  strings:
    $s1 = "LIte&T4" fullword ascii
    $s2 = "PUky[HJ" fullword ascii
    $s3 = "#qsD:Homo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}