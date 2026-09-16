import "pe"
rule Microsoft_Visual_C__ {
  strings:
    $a0 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }
    $a1 = { 8B 44 24 08 83 ?? ?? 74 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}