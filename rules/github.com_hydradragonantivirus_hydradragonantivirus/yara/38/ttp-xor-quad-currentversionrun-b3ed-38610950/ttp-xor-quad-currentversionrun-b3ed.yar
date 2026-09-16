rule TTP_XOR_QUAD_CurrentVersionRun_b3ed {
  strings:
    $key_b3ed = { e0 82 [2] c4 8c [2] ef a0 [2] c1 82 [2] d5 99 [2] da 83 [2] c4 9e [2] c6 9f [2] dd 99 [2] c1 9e [2] dd b1 }

  condition:
    any of them
}