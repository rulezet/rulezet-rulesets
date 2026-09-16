import "pe"
rule DxPack_V0_86____Dxd_____Sign_By_fly {
  strings:
    $a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }

  condition:
    $a0 at pe.entry_point
}