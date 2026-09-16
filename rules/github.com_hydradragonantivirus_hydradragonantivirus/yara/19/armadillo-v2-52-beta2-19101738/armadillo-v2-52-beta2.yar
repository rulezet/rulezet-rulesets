import "pe"
rule Armadillo_v2_52_beta2 {
  strings:
    $a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }

  condition:
    $a0 at pe.entry_point
}