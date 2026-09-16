rule TTP_XOR_QUAD_CurrentVersionRun_3cd5 {
  strings:
    $key_3cd5 = { 6f ba [2] 4b b4 [2] 60 98 [2] 4e ba [2] 5a a1 [2] 55 bb [2] 4b a6 [2] 49 a7 [2] 52 a1 [2] 4e a6 [2] 52 89 }

  condition:
    any of them
}