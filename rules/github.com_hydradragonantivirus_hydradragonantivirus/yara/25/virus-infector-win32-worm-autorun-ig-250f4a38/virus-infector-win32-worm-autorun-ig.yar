rule Virus_Infector_Win32_Worm_Autorun_IG {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Worm.Autorun.IG.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c224de45fcc4884d224d202ec2929e4c564a32653d5efb01cbc4c803cd9300fd"

  strings:
    $s1 = "6:24:47 AMMam cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}