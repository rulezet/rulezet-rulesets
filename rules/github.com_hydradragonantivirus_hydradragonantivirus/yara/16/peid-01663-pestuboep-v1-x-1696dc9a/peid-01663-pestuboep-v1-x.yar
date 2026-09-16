rule PEiD_01663_PeStubOEP_v1_x_ {
  meta:
    description = "[PeStubOEP v1.x]"
    ep_only     = "false"

  strings:
    $a = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }

  condition:
    $a
}