rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cd90c12f59227b2a93dbb7b29a9d609e3ae6255189f9b2bb367b09fc849a257"

  strings:
    $s1 = "ation error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}