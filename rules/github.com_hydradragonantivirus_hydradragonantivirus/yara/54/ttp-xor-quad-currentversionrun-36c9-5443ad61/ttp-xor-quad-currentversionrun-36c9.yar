rule TTP_XOR_QUAD_CurrentVersionRun_36c9 {
  strings:
    $key_36c9 = { 65 a6 [2] 41 a8 [2] 6a 84 [2] 44 a6 [2] 50 bd [2] 5f a7 [2] 41 ba [2] 43 bb [2] 58 bd [2] 44 ba [2] 58 95 }

  condition:
    any of them
}