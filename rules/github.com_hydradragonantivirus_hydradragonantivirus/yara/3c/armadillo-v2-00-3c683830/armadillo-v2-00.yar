import "pe"
rule Armadillo_v2_00 {
  strings:
    $a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a0 at pe.entry_point
}