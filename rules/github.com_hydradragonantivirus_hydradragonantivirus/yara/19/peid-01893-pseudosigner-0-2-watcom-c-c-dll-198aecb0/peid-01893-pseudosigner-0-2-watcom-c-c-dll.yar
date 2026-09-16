rule PEiD_01893_PseudoSigner_0_2__Watcom_C_C___DLL__ {
  meta:
    description = "[PseudoSigner 0.2 [Watcom C/C++ DLL]]"
    ep_only     = "true"

  strings:
    $a = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

  condition:
    $a
}