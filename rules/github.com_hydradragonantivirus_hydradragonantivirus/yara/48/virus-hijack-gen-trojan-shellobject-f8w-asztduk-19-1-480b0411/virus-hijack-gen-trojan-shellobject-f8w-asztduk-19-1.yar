rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "737e66cdaa351c4db96f30b90595b6b1d86f99279692970cf7ac6730f27f87ae"

  strings:
    $s1 = "Leaders agree to review EU policies" fullword ascii
    $s2 = "Lose a little advice on obesity" fullword ascii
    $s3 = "French police move into Calais camps" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}