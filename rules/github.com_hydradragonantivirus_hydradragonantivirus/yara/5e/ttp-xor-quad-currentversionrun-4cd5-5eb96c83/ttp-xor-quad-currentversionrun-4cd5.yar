rule TTP_XOR_QUAD_CurrentVersionRun_4cd5 {
  strings:
    $key_4cd5 = { 1f ba [2] 3b b4 [2] 10 98 [2] 3e ba [2] 2a a1 [2] 25 bb [2] 3b a6 [2] 39 a7 [2] 22 a1 [2] 3e a6 [2] 22 89 }

  condition:
    any of them
}