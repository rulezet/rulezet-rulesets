rule TTP_XOR_QUAD_CurrentVersionRun_b446 {
  strings:
    $key_b446 = { e7 29 [2] c3 27 [2] e8 0b [2] c6 29 [2] d2 32 [2] dd 28 [2] c3 35 [2] c1 34 [2] da 32 [2] c6 35 [2] da 1a }

  condition:
    any of them
}