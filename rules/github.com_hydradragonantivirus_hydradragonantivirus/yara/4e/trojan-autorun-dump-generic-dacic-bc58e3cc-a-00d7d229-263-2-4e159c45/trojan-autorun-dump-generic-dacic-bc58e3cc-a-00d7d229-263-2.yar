rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_263_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_263_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e578ece9d42ad3675227135b2e33a9051d4a74c685e0f9c52c45bda1de0f7979"

  strings:
    $s1 = "?kernel" fullword ascii
    $s2 = "#BOUNDARY#" fullword ascii
    $s3 = "^}TYPE" fullword ascii
    $s4 = "S * FROMf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}