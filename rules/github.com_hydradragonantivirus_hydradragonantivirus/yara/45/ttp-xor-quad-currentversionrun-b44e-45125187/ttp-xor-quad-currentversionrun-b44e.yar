rule TTP_XOR_QUAD_CurrentVersionRun_b44e {
  strings:
    $key_b44e = { e7 21 [2] c3 2f [2] e8 03 [2] c6 21 [2] d2 3a [2] dd 20 [2] c3 3d [2] c1 3c [2] da 3a [2] c6 3d [2] da 12 }

  condition:
    any of them
}