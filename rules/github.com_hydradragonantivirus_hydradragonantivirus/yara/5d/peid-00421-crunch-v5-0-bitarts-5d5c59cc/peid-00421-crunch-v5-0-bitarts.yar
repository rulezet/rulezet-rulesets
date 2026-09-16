rule PEiD_00421_Crunch_V5_0____Bitarts_ {
  meta:
    description = "[Crunch V5.0 -> Bitarts]"
    ep_only     = "true"

  strings:
    $a = { EB 15 03 00 00 00 06 }

  condition:
    $a
}