rule TTP_XOR_QUAD_CurrentVersionRun_b370 {
  strings:
    $key_b370 = { e0 1f [2] c4 11 [2] ef 3d [2] c1 1f [2] d5 04 [2] da 1e [2] c4 03 [2] c6 02 [2] dd 04 [2] c1 03 [2] dd 2c }

  condition:
    any of them
}