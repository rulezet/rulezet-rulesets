rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d5a282853812f63993b9a04668e793629a4973c2b87fcf0d7bf20a86227cc85"

  strings:
    $s1 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}