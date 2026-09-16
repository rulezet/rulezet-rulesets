rule Virus_Hijack_Trojan_GenericKDZ_98388_74_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64e3dffde21bf3b9d359a3ffeb137e6e0f372a8f67c16ad573ec2f3abafcf9d4"

  strings:
    $s1 = "q!colA(F" fullword ascii
    $s2 = "HF!GAGE" fullword ascii
    $s3 = " wacK{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}