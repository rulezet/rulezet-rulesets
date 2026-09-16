rule PEiD_00417_Crunch_5___Fusion_4____Bit_Arts_ {
  meta:
    description = "[Crunch 5 / Fusion 4 -> Bit-Arts]"
    ep_only     = "true"

  strings:
    $a = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 }

  condition:
    $a
}