rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9366e785a4f0c5397bebb0917c479a702d12c04c184e3d83f95b40a839df1e14"

  strings:
    $s1 = "Darkick Commander" fullword ascii
    $s2 = "Font(TD" fullword ascii
    $s3 = "Color`ND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}