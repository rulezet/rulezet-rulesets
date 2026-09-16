rule TTP_XOR_QUAD_CurrentVersionRun_b386 {
  strings:
    $key_b386 = { e0 e9 [2] c4 e7 [2] ef cb [2] c1 e9 [2] d5 f2 [2] da e8 [2] c4 f5 [2] c6 f4 [2] dd f2 [2] c1 f5 [2] dd da }

  condition:
    any of them
}