rule TTP_XOR_QUAD_CurrentVersionRun_b458 {
  strings:
    $key_b458 = { e7 37 [2] c3 39 [2] e8 15 [2] c6 37 [2] d2 2c [2] dd 36 [2] c3 2b [2] c1 2a [2] da 2c [2] c6 2b [2] da 04 }

  condition:
    any of them
}