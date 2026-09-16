rule TTP_XOR_QUAD_CurrentVersionRun_b4a4 {
  strings:
    $key_b4a4 = { e7 cb [2] c3 c5 [2] e8 e9 [2] c6 cb [2] d2 d0 [2] dd ca [2] c3 d7 [2] c1 d6 [2] da d0 [2] c6 d7 [2] da f8 }

  condition:
    any of them
}