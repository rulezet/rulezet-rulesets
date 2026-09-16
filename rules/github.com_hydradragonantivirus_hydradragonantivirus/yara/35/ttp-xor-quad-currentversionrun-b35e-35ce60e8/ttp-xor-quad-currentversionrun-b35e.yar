rule TTP_XOR_QUAD_CurrentVersionRun_b35e {
  strings:
    $key_b35e = { e0 31 [2] c4 3f [2] ef 13 [2] c1 31 [2] d5 2a [2] da 30 [2] c4 2d [2] c6 2c [2] dd 2a [2] c1 2d [2] dd 02 }

  condition:
    any of them
}