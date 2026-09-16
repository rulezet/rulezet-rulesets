rule TTP_XOR_QUAD_CurrentVersionRun_b31a {
  strings:
    $key_b31a = { e0 75 [2] c4 7b [2] ef 57 [2] c1 75 [2] d5 6e [2] da 74 [2] c4 69 [2] c6 68 [2] dd 6e [2] c1 69 [2] dd 46 }

  condition:
    any of them
}