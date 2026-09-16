import "pe"
rule tElock_V0_98_Special_Build____forgot___heXer_____Sign_By_fly {
  strings:
    $a0 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }

  condition:
    $a0 at pe.entry_point
}