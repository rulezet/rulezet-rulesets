rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_aiy413e_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@aiy413e_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7540b94658ded72853c3c37716211ef2b37e1b36ec13cef29a8f90b20980ff60"

  strings:
    $s1 = "tund{ppd{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}