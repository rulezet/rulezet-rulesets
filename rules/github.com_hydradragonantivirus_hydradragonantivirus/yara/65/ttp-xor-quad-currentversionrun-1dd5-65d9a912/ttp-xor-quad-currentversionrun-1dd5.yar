rule TTP_XOR_QUAD_CurrentVersionRun_1dd5 {
  strings:
    $key_1dd5 = { 4e ba [2] 6a b4 [2] 41 98 [2] 6f ba [2] 7b a1 [2] 74 bb [2] 6a a6 [2] 68 a7 [2] 73 a1 [2] 6f a6 [2] 73 89 }

  condition:
    any of them
}