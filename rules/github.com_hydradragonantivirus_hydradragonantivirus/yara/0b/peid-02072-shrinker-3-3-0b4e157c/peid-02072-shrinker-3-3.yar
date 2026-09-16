rule PEiD_02072_Shrinker_3_3_ {
  meta:
    description = "[Shrinker 3.3]"
    ep_only     = "false"

  strings:
    $a = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

  condition:
    $a
}