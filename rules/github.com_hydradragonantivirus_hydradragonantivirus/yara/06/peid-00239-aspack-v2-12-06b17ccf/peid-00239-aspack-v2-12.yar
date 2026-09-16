rule PEiD_00239_ASPack_v2_12_ {
  meta:
    description = "[ASPack v2.12]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

  condition:
    $a
}