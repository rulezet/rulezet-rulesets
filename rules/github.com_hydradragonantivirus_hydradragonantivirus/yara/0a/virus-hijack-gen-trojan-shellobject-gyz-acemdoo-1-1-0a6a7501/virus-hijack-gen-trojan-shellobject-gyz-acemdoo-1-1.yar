rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aCEmdoo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aCEmdoo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78e453488342aa1f72162327cee20352fdf48dfcc58726bbaefb8c51c9c3cdfa"

  strings:
    $s1 = "Avaunt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}