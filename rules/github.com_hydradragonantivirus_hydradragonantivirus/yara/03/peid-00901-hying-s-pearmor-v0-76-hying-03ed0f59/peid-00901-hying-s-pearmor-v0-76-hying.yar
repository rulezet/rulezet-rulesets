rule PEiD_00901_hying_s_PEArmor_V0_76____hying_ {
  meta:
    description = "[hying's PEArmor V0.76 -> hying]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }

  condition:
    $a
}