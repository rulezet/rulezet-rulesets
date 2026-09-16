rule TTP_XOR_QUAD_CurrentVersionRun_b474 {
  strings:
    $key_b474 = { e7 1b [2] c3 15 [2] e8 39 [2] c6 1b [2] d2 00 [2] dd 1a [2] c3 07 [2] c1 06 [2] da 00 [2] c6 07 [2] da 28 }

  condition:
    any of them
}