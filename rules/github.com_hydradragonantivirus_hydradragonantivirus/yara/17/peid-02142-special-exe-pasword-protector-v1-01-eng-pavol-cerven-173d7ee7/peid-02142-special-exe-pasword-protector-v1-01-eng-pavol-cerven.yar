rule PEiD_02142_Special_EXE_Pasword_Protector_v1_01__Eng_____Pavol_Cerven_ {
  meta:
    description = "[Special EXE Pasword Protector v1.01 (Eng) -> Pavol Cerven]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }

  condition:
    $a
}