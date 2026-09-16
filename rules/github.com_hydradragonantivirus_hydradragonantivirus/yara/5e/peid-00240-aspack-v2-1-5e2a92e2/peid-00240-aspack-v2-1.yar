rule PEiD_00240_ASPack_v2_1_ {
  meta:
    description = "[ASPack v2.1]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

  condition:
    $a
}