rule Virus_Hijack_Trojan_GenericKDZ_105924_496_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_496_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acac7c4b3af93554d72e5a84b8c0041de072e9ee12eed6e644e27e2e1b74ee51"

  strings:
    $s1 = "kIBy#-,Ro/-" fullword ascii
    $s2 = "h]kiLL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}