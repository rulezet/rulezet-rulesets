rule TTP_XOR_QUAD_CurrentVersionRun_b459 {
  strings:
    $key_b459 = { e7 36 [2] c3 38 [2] e8 14 [2] c6 36 [2] d2 2d [2] dd 37 [2] c3 2a [2] c1 2b [2] da 2d [2] c6 2a [2] da 05 }

  condition:
    any of them
}