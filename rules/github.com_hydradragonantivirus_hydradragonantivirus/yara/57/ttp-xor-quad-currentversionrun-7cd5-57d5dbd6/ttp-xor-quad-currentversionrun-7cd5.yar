rule TTP_XOR_QUAD_CurrentVersionRun_7cd5 {
  strings:
    $key_7cd5 = { 2f ba [2] 0b b4 [2] 20 98 [2] 0e ba [2] 1a a1 [2] 15 bb [2] 0b a6 [2] 09 a7 [2] 12 a1 [2] 0e a6 [2] 12 89 }

  condition:
    any of them
}