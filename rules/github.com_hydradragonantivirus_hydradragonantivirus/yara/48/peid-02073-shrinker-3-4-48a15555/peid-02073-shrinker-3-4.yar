rule PEiD_02073_Shrinker_3_4_ {
  meta:
    description = "[Shrinker 3.4]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }

  condition:
    $a
}