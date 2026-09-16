rule TTP_XOR_QUAD_CurrentVersionRun_b307 {
  strings:
    $key_b307 = { e0 68 [2] c4 66 [2] ef 4a [2] c1 68 [2] d5 73 [2] da 69 [2] c4 74 [2] c6 75 [2] dd 73 [2] c1 74 [2] dd 5b }

  condition:
    any of them
}