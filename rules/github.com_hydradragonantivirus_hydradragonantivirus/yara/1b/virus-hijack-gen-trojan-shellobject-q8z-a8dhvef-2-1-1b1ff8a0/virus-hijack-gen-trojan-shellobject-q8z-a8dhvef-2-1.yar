rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_a8dhVef_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@a8dhVef_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba6bf10328f506040b9fa6a8bb98a135dfe04c535df8a6b552b12d95ececeddc"

  strings:
    $s1 = "Z(jYNx" fullword ascii
    $s2 = "\"fOUlK?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}