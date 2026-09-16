rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14eb0465e11777d79edf5131e44c685c1c72820c2662782cec9c998bf03ec51d"

  strings:
    $s1 = "MWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}