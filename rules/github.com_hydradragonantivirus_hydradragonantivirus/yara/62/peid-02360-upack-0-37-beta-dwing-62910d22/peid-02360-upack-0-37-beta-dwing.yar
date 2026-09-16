rule PEiD_02360_Upack_0_37_beta____Dwing_ {
  meta:
    description = "[Upack 0.37 beta -> Dwing]"
    ep_only     = "false"

  strings:
    $a = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

  condition:
    $a
}