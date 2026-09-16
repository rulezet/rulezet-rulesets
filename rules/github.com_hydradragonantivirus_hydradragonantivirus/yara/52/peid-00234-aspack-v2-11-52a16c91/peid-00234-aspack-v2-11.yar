rule PEiD_00234_ASPack_v2_11_ {
  meta:
    description = "[ASPack v2.11]"
    ep_only     = "true"

  strings:
    $a = { 60 E9 3D 04 00 00 }

  condition:
    $a
}