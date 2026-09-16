rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5ca6038c05df1754da44f641789799c82a24e5f6111e04f6bda442d19fd4ddf"

  strings:
    $s1 = "qWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}