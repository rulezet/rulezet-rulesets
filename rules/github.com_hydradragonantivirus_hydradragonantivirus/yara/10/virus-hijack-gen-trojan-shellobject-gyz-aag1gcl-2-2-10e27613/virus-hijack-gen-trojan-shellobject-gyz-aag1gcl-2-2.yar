rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8da877fe4e998558745aae992d41aba69b7374183ed85b5aac6d93145597f990"

  strings:
    $s1 = " Data:E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}