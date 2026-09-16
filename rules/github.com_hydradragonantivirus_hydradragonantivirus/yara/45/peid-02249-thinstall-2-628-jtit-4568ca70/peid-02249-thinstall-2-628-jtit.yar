rule PEiD_02249_Thinstall_2_628____Jtit_ {
  meta:
    description = "[Thinstall 2.628 -> Jtit]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 }

  condition:
    $a
}