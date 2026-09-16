rule Virus_Hijack_Trojan_GenericKDZ_105924_313_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_313_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37de3809a8bce491e8c307537ead571dac5f380e4fef4906e2d874955c48a038"

  strings:
    $s1 = "StOB>$S" fullword ascii
    $s2 = "]gale," fullword ascii
    $s3 = "8=hx@praM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}