import "pe"
rule tElock_V0_99_V1_0_Private____tE______Sign_By_fly {
  strings:
    $a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}