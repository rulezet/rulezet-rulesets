rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc29618306110de1f98cd2c755912d44fb7d472ef8c12d3998445c703274fa23"

  strings:
    $s1 = "NWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "{PIlI<Mx R9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}