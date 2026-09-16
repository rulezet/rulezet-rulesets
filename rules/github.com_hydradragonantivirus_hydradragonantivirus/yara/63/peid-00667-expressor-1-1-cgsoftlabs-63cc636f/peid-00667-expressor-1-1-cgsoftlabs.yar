rule PEiD_00667_eXPressor_1_1____CGSoftLabs_ {
  meta:
    description = "[eXPressor 1.1 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }

  condition:
    $a
}