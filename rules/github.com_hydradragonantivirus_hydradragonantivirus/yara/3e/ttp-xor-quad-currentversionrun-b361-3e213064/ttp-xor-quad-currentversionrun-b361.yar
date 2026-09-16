rule TTP_XOR_QUAD_CurrentVersionRun_b361 {
  strings:
    $key_b361 = { e0 0e [2] c4 00 [2] ef 2c [2] c1 0e [2] d5 15 [2] da 0f [2] c4 12 [2] c6 13 [2] dd 15 [2] c1 12 [2] dd 3d }

  condition:
    any of them
}