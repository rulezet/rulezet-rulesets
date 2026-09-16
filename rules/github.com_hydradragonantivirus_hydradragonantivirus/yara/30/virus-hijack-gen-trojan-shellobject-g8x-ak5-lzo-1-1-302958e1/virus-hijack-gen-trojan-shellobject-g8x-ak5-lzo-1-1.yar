rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c0afc516c4c77f364e1f0705ed5271eb6e4a173d6bf5f21d7f231c00acf0ac1"

  strings:
    $s1 = "Deiform" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}