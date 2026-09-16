rule TTP_XOR_QUAD_CurrentVersionRun_2dd5 {
  strings:
    $key_2dd5 = { 7e ba [2] 5a b4 [2] 71 98 [2] 5f ba [2] 4b a1 [2] 44 bb [2] 5a a6 [2] 58 a7 [2] 43 a1 [2] 5f a6 [2] 43 89 }

  condition:
    any of them
}