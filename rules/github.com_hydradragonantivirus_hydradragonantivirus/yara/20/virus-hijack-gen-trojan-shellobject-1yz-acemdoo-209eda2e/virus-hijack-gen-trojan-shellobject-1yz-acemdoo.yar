rule Virus_Hijack_Gen_Trojan_ShellObject_1yZ_aCEmdoo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.1yZ@aCEmdoo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9e6c4e491330fe4adc1d57cf74d013042642224cb8c2df7c7f70b4ebb2c3065"

  strings:
    $s1 = "speC@/2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}