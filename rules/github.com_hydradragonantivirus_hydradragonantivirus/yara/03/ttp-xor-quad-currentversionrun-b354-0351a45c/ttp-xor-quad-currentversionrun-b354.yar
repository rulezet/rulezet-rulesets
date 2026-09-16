rule TTP_XOR_QUAD_CurrentVersionRun_b354 {
  strings:
    $key_b354 = { e0 3b [2] c4 35 [2] ef 19 [2] c1 3b [2] d5 20 [2] da 3a [2] c4 27 [2] c6 26 [2] dd 20 [2] c1 27 [2] dd 08 }

  condition:
    any of them
}