rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aqza5Lj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aqza5Lj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5b77a3425dc806c4ce8541980c603a49ea83e64b12673ad4a08b740edd457c2"

  strings:
    $s1 = "~America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}