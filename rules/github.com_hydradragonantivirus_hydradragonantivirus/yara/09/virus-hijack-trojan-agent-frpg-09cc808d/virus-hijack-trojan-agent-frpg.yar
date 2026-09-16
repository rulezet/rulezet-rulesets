rule Virus_Hijack_Trojan_Agent_FRPG {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.FRPG.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "621bd32743434a7b244ba0eb01eb974a9f8debc452e04062e9d907ec27546c4b"

  strings:
    $s1 = "chocolatey - shim" fullword wide
    $s2 = "0.10.5 - shim 0.8.1" fullword wide
    $s3 = "\"Target" fullword ascii
    $s4 = "7-Zip 17.00 beta (x86) : Copyright (c) 1999-2017 Igor Pavlov : 2017-04-29" fullword ascii
    $s5 = "Copyright (c) 1999-2017 Igor Pavlov" fullword wide
    $s6 = " 2017 Chocolatey Software, Inc.. Copyright " fullword wide
    $s7 = "17.00 beta" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}