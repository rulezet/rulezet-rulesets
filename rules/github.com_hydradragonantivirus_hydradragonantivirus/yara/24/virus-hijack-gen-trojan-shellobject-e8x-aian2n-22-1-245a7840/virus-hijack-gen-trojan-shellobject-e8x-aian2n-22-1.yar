rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0438b9fd849f4116d4c8d21fcebf1eebc23d7e92553ef1c2d8bf3ab7846efb17"

  strings:
    $s1 = "fREe#u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}