import "pe"
rule Shrinker_v3_3 {
  strings:
    $a0 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

  condition:
    $a0 at pe.entry_point
}