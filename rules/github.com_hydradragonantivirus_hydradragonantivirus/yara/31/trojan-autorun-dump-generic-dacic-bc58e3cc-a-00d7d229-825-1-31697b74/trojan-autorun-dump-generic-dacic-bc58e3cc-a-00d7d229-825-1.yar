rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_825_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_825_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7669460e4f1ae55f9deecea58c385355745fa1dedb673e69da3765c0d507e9c5"

  strings:
    $s1 = "jsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii
    $s2 = "E'HWk UEe&UPjrz^m>Y[*RokE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}