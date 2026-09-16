import "pe"
rule Microsoft_Visual_C___v6_0_SPx {
  strings:
    $a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }
    $a1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}