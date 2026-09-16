rule Trojan_Sysbot_Worm_Ludbaruma_B_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Worm.Ludbaruma.B_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1017594324734579def4bbd138811567e201297b012eac464fb6e27f4efa1095"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}