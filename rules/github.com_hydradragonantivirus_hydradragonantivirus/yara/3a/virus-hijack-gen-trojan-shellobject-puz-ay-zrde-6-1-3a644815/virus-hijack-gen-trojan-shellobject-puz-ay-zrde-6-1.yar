rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88d954dad3b8f29cdcd4549f45625ec6e575a38695d3ae52bf513f75282218d1"

  strings:
    $s1 = "BoiL%KX\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}