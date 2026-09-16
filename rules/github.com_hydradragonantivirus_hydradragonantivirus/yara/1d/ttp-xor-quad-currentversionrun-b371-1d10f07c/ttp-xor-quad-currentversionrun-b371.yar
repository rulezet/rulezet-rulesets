rule TTP_XOR_QUAD_CurrentVersionRun_b371 {
  strings:
    $key_b371 = { e0 1e [2] c4 10 [2] ef 3c [2] c1 1e [2] d5 05 [2] da 1f [2] c4 02 [2] c6 03 [2] dd 05 [2] c1 02 [2] dd 2d }

  condition:
    any of them
}