rule TTP_XOR_QUAD_CurrentVersionRun_b31b {
  strings:
    $key_b31b = { e0 74 [2] c4 7a [2] ef 56 [2] c1 74 [2] d5 6f [2] da 75 [2] c4 68 [2] c6 69 [2] dd 6f [2] c1 68 [2] dd 47 }

  condition:
    any of them
}