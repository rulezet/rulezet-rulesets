rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "970bba1aafad41de0851f3af753d7ec01a2e0f0d74feae27bc462b1eb348ecfd"

  strings:
    $s1 = "Infinitely" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}