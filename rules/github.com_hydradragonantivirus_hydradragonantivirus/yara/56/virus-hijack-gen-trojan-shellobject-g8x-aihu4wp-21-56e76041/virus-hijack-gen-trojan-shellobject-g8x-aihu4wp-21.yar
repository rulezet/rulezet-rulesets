rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3552f05bf737da0434a8f56b53be8682b135cfb1d8e1e927580b2de319d10531"

  strings:
    $s1 = "iWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}