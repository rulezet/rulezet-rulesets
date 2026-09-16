rule PEiD_00198_ASDPack_2_0____asd_ {
  meta:
    description = "[ASDPack 2.0 -> asd]"
    ep_only     = "true"

  strings:
    $a = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

  condition:
    $a
}