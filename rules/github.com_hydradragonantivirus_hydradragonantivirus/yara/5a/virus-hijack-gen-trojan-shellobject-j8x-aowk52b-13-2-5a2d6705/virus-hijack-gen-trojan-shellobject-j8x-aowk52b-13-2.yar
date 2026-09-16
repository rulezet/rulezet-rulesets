rule Virus_Hijack_Gen_Trojan_ShellObject_j8X_aOWk52b_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8X@aOWk52b_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a8ea28f17c9373d02698204d2561a89dc736b1c61f41461e6c0094b844a6c58"

  strings:
    $s1 = "Kl]KUla" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}