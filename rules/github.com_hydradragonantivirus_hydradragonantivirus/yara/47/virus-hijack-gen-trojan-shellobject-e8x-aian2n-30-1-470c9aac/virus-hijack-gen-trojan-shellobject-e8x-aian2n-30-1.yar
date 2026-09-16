rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf22fc2999b8f810143b25aefb063d481993384bd48ad3902d7c486e356eb86"

  strings:
    $s1 = "alive??" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}