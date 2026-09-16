rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cad2cc3036e3faaf03600e3e61bcd8d5cd12657a3a8a733c2d4a3a02e14ecec6"

  strings:
    $s1 = "/\\What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}