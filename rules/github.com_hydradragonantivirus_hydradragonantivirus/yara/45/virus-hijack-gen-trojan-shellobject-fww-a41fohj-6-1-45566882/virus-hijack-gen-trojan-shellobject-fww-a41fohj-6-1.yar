rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1223379f7039dab81163512d2b3ccc6bc3097b7a431d76484cd5c141c006623c"

  strings:
    $s1 = "The ordinal %d could not be located in the DLL %s." fullword ascii
    $s2 = "The procedure %s could not be located in the DLL %s." fullword ascii
    $s3 = "Application corrupt." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}