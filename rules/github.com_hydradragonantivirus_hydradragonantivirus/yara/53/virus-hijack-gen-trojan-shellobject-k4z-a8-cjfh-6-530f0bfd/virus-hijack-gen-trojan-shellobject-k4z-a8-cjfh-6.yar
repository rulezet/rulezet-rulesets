rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_a8_cJFh_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@a8!cJFh_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edf9b15f39ca1407d98ef47951fcda0c3f4229b5dbf84f5bbaf99826d016f254"

  strings:
    $s1 = ">buNg%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}