rule PEiD_00837_FSG_v1_31_ {
  meta:
    description = "[FSG v1.31]"
    ep_only     = "true"

  strings:
    $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

  condition:
    $a
}