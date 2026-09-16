rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2d7c30cb3ca50ce1ec8c945da19b4dee9d702bbb204978ac96ba09c623768c"

  strings:
    $s1 = "  ilia@valley.ru" fullword ascii
    $s2 = "Action(=C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}