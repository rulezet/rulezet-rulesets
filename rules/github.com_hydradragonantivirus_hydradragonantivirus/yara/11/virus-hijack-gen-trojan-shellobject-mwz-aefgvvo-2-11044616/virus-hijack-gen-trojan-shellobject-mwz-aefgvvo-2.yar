rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "945092b1b19d8f2a2c9b58fae513cdc0997ac2430a627b570d477180d40a65b7"

  strings:
    $s1 = "G&shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}