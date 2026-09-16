rule TTP_XOR_QUAD_CurrentVersionRun_b387 {
  strings:
    $key_b387 = { e0 e8 [2] c4 e6 [2] ef ca [2] c1 e8 [2] d5 f3 [2] da e9 [2] c4 f4 [2] c6 f5 [2] dd f3 [2] c1 f4 [2] dd db }

  condition:
    any of them
}