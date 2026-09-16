rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d6ecf3bdffc14c5b148ec701de70f4efdd5be3add2dfecca03c67a9dbb37fe"

  strings:
    $s1 = ")trAG[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}