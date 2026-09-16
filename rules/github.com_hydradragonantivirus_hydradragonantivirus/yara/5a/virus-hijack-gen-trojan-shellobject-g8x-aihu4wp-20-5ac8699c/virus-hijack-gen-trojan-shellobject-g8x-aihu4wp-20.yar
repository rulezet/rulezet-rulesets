rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a2a8d1614ff29b8093dd8fbd6991c13b17feb49e86e7d87ee0dc1bd9abe0209"

  strings:
    $s1 = "p3What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}