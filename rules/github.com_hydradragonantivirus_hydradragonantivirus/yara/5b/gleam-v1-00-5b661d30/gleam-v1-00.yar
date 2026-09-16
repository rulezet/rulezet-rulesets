import "pe"
rule Gleam_v1_00 {
  strings:
    $a0 = { 83 EC 0C 53 56 57 E8 24 02 00 }

  condition:
    $a0 at pe.entry_point
}