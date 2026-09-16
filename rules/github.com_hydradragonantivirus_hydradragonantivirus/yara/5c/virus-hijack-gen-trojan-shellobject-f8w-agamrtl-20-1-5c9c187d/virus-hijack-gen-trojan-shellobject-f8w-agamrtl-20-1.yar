rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7e6971088804faaabee7d975002041e1c3bc81c1466731dc8dbde286ae9c32a"

  strings:
    $s1 = "Windows host process (Rundll32)" fullword ascii
    $s2 = "dg3ypDAonQcOidMs0w.WP6RZJql8gZrNhVA9v+RJDcsuMfOxrTCYImPe+iGR41459RDH4FvPdNk`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s3 = ">Copyright (c) Microsoft Corporation. All rights reserved. 2020" fullword ascii
    $s4 = "Copyright (c) Microsoft Corporation. All rights reserved. 2020" fullword wide
    $s5 = "<Start>b__a" fullword ascii
    $s6 = "BlackJack" fullword ascii
    $s7 = "PanelWork" fullword ascii
    $s8 = "<Stop>b__e" fullword ascii
    $s9 = "<Module>{075B8D90-E65F-45C2-B8A7-CF4226D3141F}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}