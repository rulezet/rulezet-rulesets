import "pe"
rule Crinkler_V0_3_V0_4____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_____Sign_By_fly {
  strings:
    $a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

  condition:
    $a0 at pe.entry_point
}