rule TTP_XOR_QUAD_CurrentVersionRun_b323 {
  strings:
    $key_b323 = { e0 4c [2] c4 42 [2] ef 6e [2] c1 4c [2] d5 57 [2] da 4d [2] c4 50 [2] c6 51 [2] dd 57 [2] c1 50 [2] dd 7f }

  condition:
    any of them
}