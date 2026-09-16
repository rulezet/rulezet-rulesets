rule TTP_XOR_QUAD_CurrentVersionRun_b367 {
  strings:
    $key_b367 = { e0 08 [2] c4 06 [2] ef 2a [2] c1 08 [2] d5 13 [2] da 09 [2] c4 14 [2] c6 15 [2] dd 13 [2] c1 14 [2] dd 3b }

  condition:
    any of them
}