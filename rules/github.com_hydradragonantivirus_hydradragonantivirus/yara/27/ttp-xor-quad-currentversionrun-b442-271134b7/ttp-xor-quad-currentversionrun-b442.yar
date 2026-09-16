rule TTP_XOR_QUAD_CurrentVersionRun_b442 {
  strings:
    $key_b442 = { e7 2d [2] c3 23 [2] e8 0f [2] c6 2d [2] d2 36 [2] dd 2c [2] c3 31 [2] c1 30 [2] da 36 [2] c6 31 [2] da 1e }

  condition:
    any of them
}