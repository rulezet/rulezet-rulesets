rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fe06230740caa67609d4aa33a1d31c0d5f1f582991ed8575283fc90991b15c5"

  strings:
    $s1 = "E?What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}