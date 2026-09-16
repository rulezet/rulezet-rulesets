rule Virus_Hijack_Trojan_GenericKDZ_105924_157_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_157_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4d93c821c15b46cf27f2f282992ecad2f321c6c80c221f4120ef6207bcec1e3"

  strings:
    $s1 = "Please, contact the software developers with the following codes. Thank you." fullword ascii
    $s2 = "SmallMiner Silent" fullword wide
    $s3 = "([HERO(_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}