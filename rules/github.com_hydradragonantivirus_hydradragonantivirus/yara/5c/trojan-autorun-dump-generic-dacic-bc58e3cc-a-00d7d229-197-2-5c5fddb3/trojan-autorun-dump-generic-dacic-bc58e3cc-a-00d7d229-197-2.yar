rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_197_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_197_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b44e1a1a06cc614a7442fe1474a64d8ef9da61b798130e504d471279b0eb3d9"

  strings:
    $s1 = "support@amcert.net0" fullword ascii
    $s2 = "This pro[g" fullword ascii
    $s3 = "bURG@U" fullword ascii
    $s4 = "sD)dePA" fullword ascii
    $s5 = "@[E@_9@bOde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}