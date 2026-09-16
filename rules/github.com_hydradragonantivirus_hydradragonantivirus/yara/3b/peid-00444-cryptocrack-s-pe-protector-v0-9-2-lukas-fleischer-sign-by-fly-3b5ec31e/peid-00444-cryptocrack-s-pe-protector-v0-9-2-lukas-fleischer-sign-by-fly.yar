rule PEiD_00444_CRYPToCRACk_s_PE_Protector_V0_9_2____Lukas_Fleischer___Sign_by_fly_ {
  meta:
    description = "[CRYPToCRACk's PE Protector V0.9.2 -> Lukas Fleischer ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }

  condition:
    $a
}