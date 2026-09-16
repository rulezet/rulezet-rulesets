rule PEiD_01959_ReversingLabsProtector_0_7_4_beta____Ap0x_ {
  meta:
    description = "[ReversingLabsProtector 0.7.4 beta -> Ap0x]"
    ep_only     = "true"

  strings:
    $a = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }

  condition:
    $a
}