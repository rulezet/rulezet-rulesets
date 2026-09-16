rule TTP_XOR_QUAD_CurrentVersionRun_b3a5 {
  strings:
    $key_b3a5 = { e0 ca [2] c4 c4 [2] ef e8 [2] c1 ca [2] d5 d1 [2] da cb [2] c4 d6 [2] c6 d7 [2] dd d1 [2] c1 d6 [2] dd f9 }

  condition:
    any of them
}