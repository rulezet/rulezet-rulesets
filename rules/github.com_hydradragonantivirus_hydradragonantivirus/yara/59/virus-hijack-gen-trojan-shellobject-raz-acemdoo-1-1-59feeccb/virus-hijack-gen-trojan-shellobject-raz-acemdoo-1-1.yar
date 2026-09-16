rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f68accd171fd0b7925d08ae33bcc9acf1c46d3cd44b2fb6dee2d4d7c2e086937"

  strings:
    $s1 = "=1!BOUN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}