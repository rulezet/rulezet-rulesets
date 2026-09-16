rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aepfLIm_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aepfLIm_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa89845132aecba0f86aecc79534587170c731a3438b994a4e47229a0d5685e1"

  strings:
    $s1 = "Mateship" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}