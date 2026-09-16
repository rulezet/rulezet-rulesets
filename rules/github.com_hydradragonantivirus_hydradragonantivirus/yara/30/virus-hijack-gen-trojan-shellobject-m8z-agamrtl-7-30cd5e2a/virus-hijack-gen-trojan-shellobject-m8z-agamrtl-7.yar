rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fafd734e81af911760ff018033d7511bfac5085e072c917550fb312cb639e06"

  strings:
    $s1 = "saCO]hCY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}