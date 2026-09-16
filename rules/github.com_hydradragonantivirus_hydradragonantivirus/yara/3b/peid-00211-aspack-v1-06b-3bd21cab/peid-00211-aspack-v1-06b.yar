rule PEiD_00211_ASPack_v1_06b_ {
  meta:
    description = "[ASPack v1.06b]"
    ep_only     = "true"

  strings:
    $a = { 90 90 75 00 E9 }

  condition:
    $a
}