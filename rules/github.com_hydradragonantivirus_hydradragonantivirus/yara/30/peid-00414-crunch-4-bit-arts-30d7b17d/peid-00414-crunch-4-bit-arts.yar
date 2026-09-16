rule PEiD_00414_Crunch_4____Bit_Arts_ {
  meta:
    description = "[Crunch 4 -> Bit-Arts]"
    ep_only     = "true"

  strings:
    $a = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 }

  condition:
    $a
}