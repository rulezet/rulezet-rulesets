rule Virus_Hijack_Gen_Trojan_ShellObject_E8Z_a41ciQg_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005f0a73475aec7536369edd0eaf0b0d0a6391dafb67c11ca79a21830213f728"

  strings:
    $s1 = "piEr<2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}