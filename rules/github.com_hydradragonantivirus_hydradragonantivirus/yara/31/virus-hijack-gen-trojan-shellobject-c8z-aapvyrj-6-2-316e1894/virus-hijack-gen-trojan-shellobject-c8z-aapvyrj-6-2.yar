rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_aaPVyRj_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@aaPVyRj_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47762db64fe36b800fbdfd4455112fec63c0b6605293a3f18e791c25bd8cc7b5"

  strings:
    $s1 = "rOKa;[&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}