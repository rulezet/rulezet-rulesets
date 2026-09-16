rule TTP_XOR_QUAD_CurrentVersionRun_b347 {
  strings:
    $key_b347 = { e0 28 [2] c4 26 [2] ef 0a [2] c1 28 [2] d5 33 [2] da 29 [2] c4 34 [2] c6 35 [2] dd 33 [2] c1 34 [2] dd 1b }

  condition:
    any of them
}