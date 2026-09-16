rule PEiD_00948_Joiner__sign_from_pinch_25_03_2007_20_10__ {
  meta:
    description = "[Joiner (sign from pinch 25.03.2007 20:10)]"
    ep_only     = "true"

  strings:
    $a = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }

  condition:
    $a
}