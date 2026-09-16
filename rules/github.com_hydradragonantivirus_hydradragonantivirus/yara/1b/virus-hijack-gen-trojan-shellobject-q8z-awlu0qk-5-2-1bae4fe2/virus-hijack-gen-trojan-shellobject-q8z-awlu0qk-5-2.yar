rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f45135b5a26a22f2f41d6bcb53ca576f900f863f30f4c1e0857bdf95a1a902f"

  strings:
    $s1 = "E:MOko" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}