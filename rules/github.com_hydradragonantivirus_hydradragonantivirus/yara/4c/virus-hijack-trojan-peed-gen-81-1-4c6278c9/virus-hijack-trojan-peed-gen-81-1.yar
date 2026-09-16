rule Virus_Hijack_Trojan_Peed_Gen_81_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "975118cddad9362d959a8f8900610c7b14d389a9fa56db2dee6ee371472a1da1"

  strings:
    $s1 = "M,aLMa" fullword ascii
    $s2 = "U<VaIl" fullword ascii
    $s3 = "m fISt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}