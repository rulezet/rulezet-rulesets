rule TTP_XOR_QUAD_CurrentVersionRun_b473 {
  strings:
    $key_b473 = { e7 1c [2] c3 12 [2] e8 3e [2] c6 1c [2] d2 07 [2] dd 1d [2] c3 00 [2] c1 01 [2] da 07 [2] c6 00 [2] da 2f }

  condition:
    any of them
}