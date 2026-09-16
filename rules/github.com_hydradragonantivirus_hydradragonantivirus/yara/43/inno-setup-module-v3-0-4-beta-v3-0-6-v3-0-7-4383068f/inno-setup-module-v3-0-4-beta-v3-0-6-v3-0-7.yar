import "pe"
rule Inno_Setup_Module_v3_0_4_beta_v3_0_6_v3_0_7 {
  strings:
    $a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

  condition:
    $a0 at pe.entry_point
}