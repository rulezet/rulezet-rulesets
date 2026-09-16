rule TTP_XOR_QUAD_CurrentVersionRun_b4b7 {
  strings:
    $key_b4b7 = { e7 d8 [2] c3 d6 [2] e8 fa [2] c6 d8 [2] d2 c3 [2] dd d9 [2] c3 c4 [2] c1 c5 [2] da c3 [2] c6 c4 [2] da eb }

  condition:
    any of them
}