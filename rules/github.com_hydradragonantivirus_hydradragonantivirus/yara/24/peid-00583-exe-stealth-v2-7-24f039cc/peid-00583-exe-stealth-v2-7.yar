rule PEiD_00583_EXE_Stealth_v2_7_ {
  meta:
    description = "[EXE Stealth v2.7]"
    ep_only     = "true"

  strings:
    $a = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

  condition:
    $a
}