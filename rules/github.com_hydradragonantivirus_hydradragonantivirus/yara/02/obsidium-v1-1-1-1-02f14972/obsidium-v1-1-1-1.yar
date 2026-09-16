import "pe"
rule Obsidium_v1_1_1_1 {
  strings:
    $a0 = { EB 02 ?? ?? E8 E7 1C 00 00 }

  condition:
    $a0 at pe.entry_point
}