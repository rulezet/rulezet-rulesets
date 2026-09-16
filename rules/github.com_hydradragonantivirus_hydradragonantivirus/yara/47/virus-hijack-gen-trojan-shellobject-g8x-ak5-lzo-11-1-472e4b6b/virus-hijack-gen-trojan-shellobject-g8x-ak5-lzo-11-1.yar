rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d09b9bb317054cfe0125021f767b30e1517ef5059d78663de778e890e4c9c67"

  strings:
    $s1 = "Dishonor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}