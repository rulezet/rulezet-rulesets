rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2379d376905b03be0df67f7b3f57c3539e3f4d5f7d38b6ba6d64c0dce5d5f66"

  strings:
    $s1 = "IWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "\"gRaM:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}