rule TTP_XOR_QUAD_CurrentVersionRun_b315 {
  strings:
    $key_b315 = { e0 7a [2] c4 74 [2] ef 58 [2] c1 7a [2] d5 61 [2] da 7b [2] c4 66 [2] c6 67 [2] dd 61 [2] c1 66 [2] dd 49 }

  condition:
    any of them
}