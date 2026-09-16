rule TTP_XOR_QUAD_CurrentVersionRun_46c9 {
  strings:
    $key_46c9 = { 15 a6 [2] 31 a8 [2] 1a 84 [2] 34 a6 [2] 20 bd [2] 2f a7 [2] 31 ba [2] 33 bb [2] 28 bd [2] 34 ba [2] 28 95 }

  condition:
    any of them
}