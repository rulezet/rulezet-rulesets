rule TTP_XOR_QUAD_CurrentVersionRun_b377 {
  strings:
    $key_b377 = { e0 18 [2] c4 16 [2] ef 3a [2] c1 18 [2] d5 03 [2] da 19 [2] c4 04 [2] c6 05 [2] dd 03 [2] c1 04 [2] dd 2b }

  condition:
    any of them
}