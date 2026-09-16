rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "889a3885fa4855e2db8cfbe719e12e07c50ecadbf0cdf8fb266f13cfa7c7a156"

  strings:
    $s1 = ")What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}