rule Virus_Hijack_Trojan_GenericKDZ_98388_143_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_143_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "358f06f1e87d53ad1b7bc083623ae84fa42f4812c275cf1bafcea8f6c72669fc"

  strings:
    $s1 = "u[jUTe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}