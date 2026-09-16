rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d50de992d4ad006a285ee11b1a868e303d47595833aee2667234da6f07240a"

  strings:
    $s1 = "ft Visual Studio\\" fullword ascii
    $s2 = "Timer&" fullword ascii
    $s3 = "g#Conk" fullword ascii
    $s4 = "Copy@N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}