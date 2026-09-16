rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b90f2e8c2b5a7bf70a7b8fbfd8393fa5a0ce7e872cf085f72b450b4e1a22189"

  strings:
    $s1 = "{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}