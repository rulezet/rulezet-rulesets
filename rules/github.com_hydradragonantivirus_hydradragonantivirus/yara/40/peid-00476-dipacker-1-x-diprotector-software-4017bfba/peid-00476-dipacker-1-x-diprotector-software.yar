rule PEiD_00476_diPacker_1_x____diProtector_Software_ {
  meta:
    description = "[diPacker 1.x -> diProtector Software]"
    ep_only     = "true"

  strings:
    $a = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }

  condition:
    $a
}