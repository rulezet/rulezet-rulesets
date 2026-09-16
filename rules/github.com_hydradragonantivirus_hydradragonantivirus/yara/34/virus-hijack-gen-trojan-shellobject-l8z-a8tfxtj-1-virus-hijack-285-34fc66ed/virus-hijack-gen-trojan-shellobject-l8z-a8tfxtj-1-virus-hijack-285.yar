import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_l8Z_a8TFxTj_1_Virus_Hijack__285 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.l8Z@a8TFxTj_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9814f5e3f29593e7d9c184f973f178d208637250ebbd6345511189cda675e736"
    hash2       = "bce6081238d2ea3ff6609319466dffe22ab8a5f8aac6bf34de211da4829fabfc"

  strings:
    $s1 = "Qualifacts Systems Plane" fullword wide
    $s2 = "Done whether" fullword wide
    $s3 = " 2006. All rights reserved." fullword wide
    $s4 = "CLAT>D" fullword ascii
    $s5 = "F}JEFF" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "e5a4b6c7aea5d490820442671dd9e506" and (all of them)
    ) or (all of them)
}