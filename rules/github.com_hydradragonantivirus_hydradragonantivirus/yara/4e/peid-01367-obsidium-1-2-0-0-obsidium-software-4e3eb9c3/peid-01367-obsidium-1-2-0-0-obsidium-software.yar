rule PEiD_01367_Obsidium_1_2_0_0____Obsidium_Software_ {
  meta:
    description = "[Obsidium 1.2.0.0 -> Obsidium Software]"
    ep_only     = "true"

  strings:
    $a = { EB 02 ?? ?? E8 3F 1E 00 00 }

  condition:
    $a
}