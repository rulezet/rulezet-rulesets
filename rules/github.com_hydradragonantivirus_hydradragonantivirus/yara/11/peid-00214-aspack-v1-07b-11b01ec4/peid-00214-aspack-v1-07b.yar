rule PEiD_00214_ASPack_v1_07b_ {
  meta:
    description = "[ASPack v1.07b]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 75 ?? E9 }

  condition:
    $a
}