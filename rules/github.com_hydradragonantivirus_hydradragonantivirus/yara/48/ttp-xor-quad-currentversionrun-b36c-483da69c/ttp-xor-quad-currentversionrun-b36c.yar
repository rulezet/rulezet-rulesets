rule TTP_XOR_QUAD_CurrentVersionRun_b36c {
  strings:
    $key_b36c = { e0 03 [2] c4 0d [2] ef 21 [2] c1 03 [2] d5 18 [2] da 02 [2] c4 1f [2] c6 1e [2] dd 18 [2] c1 1f [2] dd 30 }

  condition:
    any of them
}