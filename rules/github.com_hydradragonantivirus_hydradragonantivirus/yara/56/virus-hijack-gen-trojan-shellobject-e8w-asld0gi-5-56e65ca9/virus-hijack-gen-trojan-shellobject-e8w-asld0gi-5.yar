rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b535fde0818daebe3454c194d665e686057a9031bff1eb9fc054261d13a821f2"

  strings:
    $s1 = "this agreement, as well as all sums remaining unpaid for programs ordered and/or services received under this agreeme`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}