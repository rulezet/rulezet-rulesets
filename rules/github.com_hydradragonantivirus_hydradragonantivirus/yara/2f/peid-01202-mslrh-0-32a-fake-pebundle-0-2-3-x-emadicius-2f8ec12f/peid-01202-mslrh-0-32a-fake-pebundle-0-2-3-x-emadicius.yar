rule PEiD_01202_MSLRH_0_32a__fake_PEBundle_0_2___3_x_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake PEBundle 0.2 - 3.x) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 }

  condition:
    $a
}