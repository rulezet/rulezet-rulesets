rule TTP_XOR_QUAD_CurrentVersionRun_b45b {
  strings:
    $key_b45b = { e7 34 [2] c3 3a [2] e8 16 [2] c6 34 [2] d2 2f [2] dd 35 [2] c3 28 [2] c1 29 [2] da 2f [2] c6 28 [2] da 07 }

  condition:
    any of them
}