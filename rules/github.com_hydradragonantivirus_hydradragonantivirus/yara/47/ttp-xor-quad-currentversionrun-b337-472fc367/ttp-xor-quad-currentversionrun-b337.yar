rule TTP_XOR_QUAD_CurrentVersionRun_b337 {
  strings:
    $key_b337 = { e0 58 [2] c4 56 [2] ef 7a [2] c1 58 [2] d5 43 [2] da 59 [2] c4 44 [2] c6 45 [2] dd 43 [2] c1 44 [2] dd 6b }

  condition:
    any of them
}