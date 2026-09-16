rule TTP_XOR_QUAD_CurrentVersionRun_0cd5 {
  strings:
    $key_0cd5 = { 5f ba [2] 7b b4 [2] 50 98 [2] 7e ba [2] 6a a1 [2] 65 bb [2] 7b a6 [2] 79 a7 [2] 62 a1 [2] 7e a6 [2] 62 89 }

  condition:
    any of them
}