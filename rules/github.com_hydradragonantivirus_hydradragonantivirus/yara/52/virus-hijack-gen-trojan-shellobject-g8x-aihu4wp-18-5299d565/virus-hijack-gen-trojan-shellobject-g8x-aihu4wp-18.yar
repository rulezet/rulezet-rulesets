rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca3afa510abfe4cb7d2f75e81512cc492626548bc8152706a8f14fd2b0b37165"

  strings:
    $s1 = "hWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "tHIg(9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}