rule TTP_XOR_QUAD_CurrentVersionRun_b3b6 {
  strings:
    $key_b3b6 = { e0 d9 [2] c4 d7 [2] ef fb [2] c1 d9 [2] d5 c2 [2] da d8 [2] c4 c5 [2] c6 c4 [2] dd c2 [2] c1 c5 [2] dd ea }

  condition:
    any of them
}