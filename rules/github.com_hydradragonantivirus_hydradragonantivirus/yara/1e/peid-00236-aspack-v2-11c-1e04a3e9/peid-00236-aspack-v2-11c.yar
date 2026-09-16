rule PEiD_00236_ASPack_v2_11c_ {
  meta:
    description = "[ASPack v2.11c]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

  condition:
    $a
}