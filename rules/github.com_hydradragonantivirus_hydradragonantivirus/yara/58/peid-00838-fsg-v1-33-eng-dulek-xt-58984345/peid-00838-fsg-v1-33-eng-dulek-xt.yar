rule PEiD_00838_FSG_v1_33__Eng_____dulek_xt_ {
  meta:
    description = "[FSG v1.33 (Eng) -> dulek/xt]"
    ep_only     = "true"

  strings:
    $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }

  condition:
    $a
}