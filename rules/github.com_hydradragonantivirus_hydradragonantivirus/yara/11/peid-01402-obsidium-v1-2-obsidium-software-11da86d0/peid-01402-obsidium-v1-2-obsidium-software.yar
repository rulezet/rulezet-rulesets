rule PEiD_01402_Obsidium_V1_2____Obsidium_Software_ {
  meta:
    description = "[Obsidium V1.2 -> Obsidium Software]"
    ep_only     = "true"

  strings:
    $a = { EB 02 ?? ?? E8 77 1E 00 00 }

  condition:
    $a
}