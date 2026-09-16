rule PEiD_02451_UPX_V1_94____Markus_Oberhumer__amp__Laszlo_Molnar__amp__John_Reiser_ {
  meta:
    description = "[UPX V1.94 -> Markus Oberhumer &amp; Laszlo Molnar &amp; John Reiser]"
    ep_only     = "false"

  strings:
    $a = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

  condition:
    $a
}