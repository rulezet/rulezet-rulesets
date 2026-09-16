rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aSt7VTp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aSt7VTp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72a38692535b6707cc8e38d5fcf83c8de9f6d4616142dc20f3c0054cc31d2274"

  strings:
    $s1 = "]&purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}