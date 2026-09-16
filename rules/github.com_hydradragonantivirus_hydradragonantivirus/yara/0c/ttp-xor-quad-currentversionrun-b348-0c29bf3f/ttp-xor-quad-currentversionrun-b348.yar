rule TTP_XOR_QUAD_CurrentVersionRun_b348 {
  strings:
    $key_b348 = { e0 27 [2] c4 29 [2] ef 05 [2] c1 27 [2] d5 3c [2] da 26 [2] c4 3b [2] c6 3a [2] dd 3c [2] c1 3b [2] dd 14 }

  condition:
    any of them
}