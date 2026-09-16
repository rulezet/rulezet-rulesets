rule PEiD_00412_Crinkler_V0_1_V0_2____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_ {
  meta:
    description = "[Crinkler V0.1-V0.2 -> Rune L.H.Stubbe and Aske Simon Christensen]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }

  condition:
    $a
}