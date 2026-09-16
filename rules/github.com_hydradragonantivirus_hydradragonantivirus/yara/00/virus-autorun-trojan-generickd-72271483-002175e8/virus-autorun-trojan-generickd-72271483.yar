rule Virus_Autorun_Trojan_GenericKD_72271483 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKD.72271483.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfc179cb2eb34e531756cd1ae5c5bf8b0408d5718c19a6c749f28624d2e0e124"

  strings:
    $s1 = "roEr@,-" fullword ascii
    $s2 = "slIm]lZ" fullword ascii
    $s3 = "D`LERP" fullword ascii
    $s4 = "ULMO'2" fullword ascii
    $s5 = "BAck]~" fullword ascii
    $s6 = "SnUG#K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}