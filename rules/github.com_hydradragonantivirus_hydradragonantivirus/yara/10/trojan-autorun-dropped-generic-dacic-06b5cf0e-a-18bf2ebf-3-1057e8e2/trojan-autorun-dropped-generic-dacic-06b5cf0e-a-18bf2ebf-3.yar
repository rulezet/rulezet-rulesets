rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_18BF2EBF_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.18BF2EBF_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "521fa9510feaac0843a9e6ce18034d6620198a89ba730b31cf7fa24404991567"

  strings:
    $s1 = "Copyright 2014 AiosrdKofdr" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}