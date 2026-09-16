rule PEiD_00781_FSG_v1_0_ {
  meta:
    description = "[FSG v1.0]"
    ep_only     = "true"

  strings:
    $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

  condition:
    $a
}