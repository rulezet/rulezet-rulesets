rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_77_1_Virus_Hijack_Gen__365 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_77_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2467cac4e72e1e7b244a0d73142dd174539a8b667831b4eac54d489522e74b6e"
    hash2       = "5325f07729f47d68aacc6f072cad00556c653c24e2a6959d4826d7979ceb2c7c"

  strings:
    $s1  = "TEMP????-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s2  = "TEMP?????-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s3  = "TEMPqbc-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s4  = "TEMP???-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s5  = "TEMP??" fullword ascii
    $s6  = "u-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s7  = "-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s8  = "??-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s9  = "?-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii
    $s10 = "???-An update to Acrobat or Reader is being installed. Please wait until installation is complete and then try again." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}