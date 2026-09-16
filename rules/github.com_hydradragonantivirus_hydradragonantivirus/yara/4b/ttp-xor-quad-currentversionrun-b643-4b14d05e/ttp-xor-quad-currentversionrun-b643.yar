rule TTP_XOR_QUAD_CurrentVersionRun_b643 {
  strings:
    $key_b643 = { e5 2c [2] c1 22 [2] ea 0e [2] c4 2c [2] d0 37 [2] df 2d [2] c1 30 [2] c3 31 [2] d8 37 [2] c4 30 [2] d8 1f }

  condition:
    any of them
}