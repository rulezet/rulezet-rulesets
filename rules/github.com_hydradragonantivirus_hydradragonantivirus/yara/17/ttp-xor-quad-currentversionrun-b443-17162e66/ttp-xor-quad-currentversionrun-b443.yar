rule TTP_XOR_QUAD_CurrentVersionRun_b443 {
  strings:
    $key_b443 = { e7 2c [2] c3 22 [2] e8 0e [2] c6 2c [2] d2 37 [2] dd 2d [2] c3 30 [2] c1 31 [2] da 37 [2] c6 30 [2] da 1f }

  condition:
    any of them
}