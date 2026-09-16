rule TTP_XOR_QUAD_CurrentVersionRun_b3b8 {
  strings:
    $key_b3b8 = { e0 d7 [2] c4 d9 [2] ef f5 [2] c1 d7 [2] d5 cc [2] da d6 [2] c4 cb [2] c6 ca [2] dd cc [2] c1 cb [2] dd e4 }

  condition:
    any of them
}