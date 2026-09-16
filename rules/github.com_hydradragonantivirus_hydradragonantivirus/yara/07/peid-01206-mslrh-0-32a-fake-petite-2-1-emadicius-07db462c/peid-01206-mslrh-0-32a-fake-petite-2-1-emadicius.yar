rule PEiD_01206_MSLRH_0_32a__fake_PEtite_2_1_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake PEtite 2.1) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB }

  condition:
    $a
}