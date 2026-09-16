rule PEiD_01894_PseudoSigner_0_2__WATCOM_C_C___EXE__ {
  meta:
    description = "[PseudoSigner 0.2 [WATCOM C/C++ EXE]]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 90 90 90 90 57 41 }

  condition:
    $a
}