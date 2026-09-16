rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "631e22419f8526a84bf468b90f5656399c166e366fc2ae55b0113ca3afeb5f3d"

  strings:
    $s1 = "2Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}