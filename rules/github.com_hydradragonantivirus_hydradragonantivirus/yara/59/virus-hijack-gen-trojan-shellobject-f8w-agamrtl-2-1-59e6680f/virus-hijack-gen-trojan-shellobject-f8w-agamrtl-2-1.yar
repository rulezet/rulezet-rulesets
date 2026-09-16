rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3403946a875fb092ba0343063284b473a01cf3e69b387b7922ce5f2478a53e9"

  strings:
    $x1 = "c:\\Users\\Administrator\\Documents\\Visual Studio 2012\\Projects\\corkscrews\\corkscrews\\obj\\Release\\corkscrews.pdb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}