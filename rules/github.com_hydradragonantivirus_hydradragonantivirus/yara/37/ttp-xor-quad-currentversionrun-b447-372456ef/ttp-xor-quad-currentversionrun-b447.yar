rule TTP_XOR_QUAD_CurrentVersionRun_b447 {
  strings:
    $key_b447 = { e7 28 [2] c3 26 [2] e8 0a [2] c6 28 [2] d2 33 [2] dd 29 [2] c3 34 [2] c1 35 [2] da 33 [2] c6 34 [2] da 1b }

  condition:
    any of them
}