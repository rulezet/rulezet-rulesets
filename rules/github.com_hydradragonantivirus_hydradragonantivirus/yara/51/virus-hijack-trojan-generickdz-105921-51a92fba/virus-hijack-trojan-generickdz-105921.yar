rule Virus_Hijack_Trojan_GenericKDZ_105921 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cfca8b7b0320865f118c3f62ad3e23bb713d3c8ce2feaf74150fa8f6005a4f8"

  strings:
    $s1 = "F2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}