rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cca295b3bde97c02d3d673394a574d751b002329dc3e632a4accfa8a8ce4b7a3"

  strings:
    $s1 = "The ordinal %d could not be located in the DLL %s." fullword ascii
    $s2 = "The procedure %s could not be located in the DLL %s." fullword ascii
    $s3 = "Application corrupt." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}