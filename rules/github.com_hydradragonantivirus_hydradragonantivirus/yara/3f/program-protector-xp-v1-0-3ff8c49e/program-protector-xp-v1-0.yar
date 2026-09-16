import "pe"
rule Program_Protector_XP_v1_0 {
  strings:
    $a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }

  condition:
    $a0 at pe.entry_point
}