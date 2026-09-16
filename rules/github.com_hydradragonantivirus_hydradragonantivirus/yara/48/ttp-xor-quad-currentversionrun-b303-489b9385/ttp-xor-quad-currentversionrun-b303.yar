rule TTP_XOR_QUAD_CurrentVersionRun_b303 {
  strings:
    $key_b303 = { e0 6c [2] c4 62 [2] ef 4e [2] c1 6c [2] d5 77 [2] da 6d [2] c4 70 [2] c6 71 [2] dd 77 [2] c1 70 [2] dd 5f }

  condition:
    any of them
}