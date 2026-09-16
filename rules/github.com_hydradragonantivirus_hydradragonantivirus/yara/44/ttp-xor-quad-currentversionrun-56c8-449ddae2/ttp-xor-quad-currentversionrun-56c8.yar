rule TTP_XOR_QUAD_CurrentVersionRun_56c8 {
  strings:
    $key_56c8 = { 05 a7 [2] 21 a9 [2] 0a 85 [2] 24 a7 [2] 30 bc [2] 3f a6 [2] 21 bb [2] 23 ba [2] 38 bc [2] 24 bb [2] 38 94 }

  condition:
    any of them
}