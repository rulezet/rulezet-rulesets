rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6642fd06bd95f1fbb8b4adca05da9355fb97d1076d25b324f812e6ea13b2084f"

  strings:
    $s1 = "owhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}