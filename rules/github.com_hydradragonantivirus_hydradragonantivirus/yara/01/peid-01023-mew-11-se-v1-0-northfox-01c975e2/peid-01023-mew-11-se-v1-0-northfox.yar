rule PEiD_01023_MEW_11_SE_v1_0____Northfox_ {
  meta:
    description = "[MEW 11 SE v1.0 -> Northfox]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C ?0 }

  condition:
    $a
}