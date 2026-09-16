rule TTP_XOR_QUAD_CurrentVersionRun_b325 {
  strings:
    $key_b325 = { e0 4a [2] c4 44 [2] ef 68 [2] c1 4a [2] d5 51 [2] da 4b [2] c4 56 [2] c6 57 [2] dd 51 [2] c1 56 [2] dd 79 }

  condition:
    any of them
}