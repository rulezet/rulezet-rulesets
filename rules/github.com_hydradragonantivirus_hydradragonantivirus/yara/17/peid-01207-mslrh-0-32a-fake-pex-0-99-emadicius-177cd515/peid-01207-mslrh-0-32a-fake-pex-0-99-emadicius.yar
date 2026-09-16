rule PEiD_01207_MSLRH_0_32a__fake_PEX_0_99_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake PEX 0.99) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 }

  condition:
    $a
}