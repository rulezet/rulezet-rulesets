rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a58d8730d26929faf468dd26966eab920e77839fd8d328d40dbf79031f790b6d"

  strings:
    $s1 = "Management Support Team1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}