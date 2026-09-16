rule TTP_XOR_QUAD_CurrentVersionRun_b495 {
  strings:
    $key_b495 = { e7 fa [2] c3 f4 [2] e8 d8 [2] c6 fa [2] d2 e1 [2] dd fb [2] c3 e6 [2] c1 e7 [2] da e1 [2] c6 e6 [2] da c9 }

  condition:
    any of them
}