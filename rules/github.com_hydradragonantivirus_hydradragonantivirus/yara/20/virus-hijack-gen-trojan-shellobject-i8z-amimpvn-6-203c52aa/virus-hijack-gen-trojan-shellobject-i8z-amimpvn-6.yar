rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "184fdeead8eaf64b9dceeaa76d83b65d8d243f984fc1df105a45bd03c5d47c1a"

  strings:
    $s1 = ",policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}