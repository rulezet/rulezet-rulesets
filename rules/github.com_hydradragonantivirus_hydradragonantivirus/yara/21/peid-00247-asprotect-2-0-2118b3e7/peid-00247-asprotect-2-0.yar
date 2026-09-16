rule PEiD_00247_ASProtect_2_0_ {
  meta:
    description = "[ASProtect 2.0]"
    ep_only     = "false"

  strings:
    $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

  condition:
    $a
}