rule TTP_XOR_QUAD_CurrentVersionRun_b357 {
  strings:
    $key_b357 = { e0 38 [2] c4 36 [2] ef 1a [2] c1 38 [2] d5 23 [2] da 39 [2] c4 24 [2] c6 25 [2] dd 23 [2] c1 24 [2] dd 0b }

  condition:
    any of them
}