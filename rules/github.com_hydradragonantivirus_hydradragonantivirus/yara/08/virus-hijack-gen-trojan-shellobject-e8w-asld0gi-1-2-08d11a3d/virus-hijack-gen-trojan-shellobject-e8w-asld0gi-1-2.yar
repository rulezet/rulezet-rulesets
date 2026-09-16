rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08e0cd632a67d46398a5549c13a161136afee02087e083a267a67c2029ea6c67"

  strings:
    $s1 = "Management Support Team1" fullword ascii
    $s2 = "R#Draw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}