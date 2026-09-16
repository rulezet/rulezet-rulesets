import "pe"
rule SoftSentry_v2_11 {
  strings:
    $a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

  condition:
    $a0 at pe.entry_point
}