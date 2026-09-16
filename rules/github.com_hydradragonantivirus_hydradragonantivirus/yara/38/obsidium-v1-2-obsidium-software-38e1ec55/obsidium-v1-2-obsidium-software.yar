import "pe"
rule Obsidium_V1_2____Obsidium_Software {
  strings:
    $a0 = { EB 02 ?? ?? E8 77 1E 00 00 }

  condition:
    $a0 at pe.entry_point
}