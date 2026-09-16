rule TTP_XOR_QUAD_CurrentVersionRun_7dd5 {
  strings:
    $key_7dd5 = { 2e ba [2] 0a b4 [2] 21 98 [2] 0f ba [2] 1b a1 [2] 14 bb [2] 0a a6 [2] 08 a7 [2] 13 a1 [2] 0f a6 [2] 13 89 }

  condition:
    any of them
}