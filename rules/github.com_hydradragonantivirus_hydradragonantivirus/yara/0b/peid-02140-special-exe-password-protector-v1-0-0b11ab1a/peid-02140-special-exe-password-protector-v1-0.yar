rule PEiD_02140_Special_EXE_Password_Protector_v1_0_ {
  meta:
    description = "[Special EXE Password Protector v1.0]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

  condition:
    $a
}