rule PEiD_03462_WinUpack_v0_30_beta____By_Dwing_ {
  meta:
    description = "[WinUpack v0.30 beta -> By Dwing]"
    ep_only     = "false"

  strings:
    $a = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }

  condition:
    $a
}