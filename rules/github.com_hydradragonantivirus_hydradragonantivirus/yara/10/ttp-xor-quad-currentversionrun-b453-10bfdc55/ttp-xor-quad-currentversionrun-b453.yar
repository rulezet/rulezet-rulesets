rule TTP_XOR_QUAD_CurrentVersionRun_b453 {
  strings:
    $key_b453 = { e7 3c [2] c3 32 [2] e8 1e [2] c6 3c [2] d2 27 [2] dd 3d [2] c3 20 [2] c1 21 [2] da 27 [2] c6 20 [2] da 0f }

  condition:
    any of them
}