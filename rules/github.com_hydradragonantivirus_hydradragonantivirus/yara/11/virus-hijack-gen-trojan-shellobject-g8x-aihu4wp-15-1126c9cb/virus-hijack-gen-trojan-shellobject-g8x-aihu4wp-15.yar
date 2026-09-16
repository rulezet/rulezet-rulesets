rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93b91fba7a5380411ac8aa0d2c3a5d2d2851ea9ae3343af0b8c304a11bf1a530"

  strings:
    $s1 = "&What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}