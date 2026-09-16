rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08bea6fef66f0070b9f35c5db9da078af5d4b59dec42480f80264f066ba99d20"

  strings:
    $s1 = "C:\\Users\\Juan\\Documents\\Visual Studio 2013\\Projects\\Base64 Crypto\\zoo\\obj\\Debug\\z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}