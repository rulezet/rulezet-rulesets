rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd12b3e0373986b2ddca3618e2593b691e862e74f905b2810779a02f27d91e15"

  strings:
    $s1 = "lOWY(ib" fullword ascii
    $s2 = "beMa>t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}