rule PEiD_01209_MSLRH_0_32a__fake_UPX_0_89_6___1_02___1_05___1_24_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake UPX 0.89.6 - 1.02 / 1.05 - 1.24) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 }

  condition:
    $a
}