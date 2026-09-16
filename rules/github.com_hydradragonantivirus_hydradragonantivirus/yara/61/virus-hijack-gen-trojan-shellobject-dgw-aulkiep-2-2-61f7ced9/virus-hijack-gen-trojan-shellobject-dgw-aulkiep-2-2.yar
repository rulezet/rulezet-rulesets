rule Virus_Hijack_Gen_Trojan_ShellObject_dGW_aulKiep_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGW@aulKiep_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90da64d10dd34ac2ea55ebea91988d6a528af89a4aa3380bf964c0d45e051d02"

  strings:
    $s1 = "d!hooN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}