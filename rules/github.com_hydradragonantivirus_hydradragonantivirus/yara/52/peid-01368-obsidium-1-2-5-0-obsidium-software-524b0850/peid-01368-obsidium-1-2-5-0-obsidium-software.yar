rule PEiD_01368_Obsidium_1_2_5_0____Obsidium_Software_ {
  meta:
    description = "[Obsidium 1.2.5.0 -> Obsidium Software]"
    ep_only     = "true"

  strings:
    $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 }

  condition:
    $a
}