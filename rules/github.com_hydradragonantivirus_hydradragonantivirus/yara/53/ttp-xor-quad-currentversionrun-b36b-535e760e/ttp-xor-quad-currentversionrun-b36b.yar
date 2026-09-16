rule TTP_XOR_QUAD_CurrentVersionRun_b36b {
  strings:
    $key_b36b = { e0 04 [2] c4 0a [2] ef 26 [2] c1 04 [2] d5 1f [2] da 05 [2] c4 18 [2] c6 19 [2] dd 1f [2] c1 18 [2] dd 37 }

  condition:
    any of them
}