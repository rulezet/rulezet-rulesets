rule TTP_XOR_QUAD_CurrentVersionRun_b345 {
  strings:
    $key_b345 = { e0 2a [2] c4 24 [2] ef 08 [2] c1 2a [2] d5 31 [2] da 2b [2] c4 36 [2] c6 37 [2] dd 31 [2] c1 36 [2] dd 19 }

  condition:
    any of them
}