rule Virus_Infector_Win32_Expiro_Gen_7_85 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_85.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "778c24763ef88dfeb4c6d6ce19861aa54e9eaa3f29da69e42137fd0254689ced"

  strings:
    $s1 = "Bite?jm" fullword ascii
    $s2 = "FriB;n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}