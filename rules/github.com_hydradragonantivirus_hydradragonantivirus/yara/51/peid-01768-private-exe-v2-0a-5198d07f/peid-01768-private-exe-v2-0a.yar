rule PEiD_01768_Private_EXE_v2_0a_ {
  meta:
    description = "[Private EXE v2.0a]"
    ep_only     = "true"

  strings:
    $a = { 53 E8 00 00 00 00 5B 8B C3 2D }

  condition:
    $a
}