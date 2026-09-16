rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc89f61ea4591bdbfb5e473395fa3155b89276af379fe55300f5177c256415a"

  strings:
    $s1 = "  ilia@valley.ru" fullword ascii
    $s2 = "Action(=C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}