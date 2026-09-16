rule TTP_XOR_QUAD_CurrentVersionRun_59c9 {
  strings:
    $key_59c9 = { 0a a6 [2] 2e a8 [2] 05 84 [2] 2b a6 [2] 3f bd [2] 30 a7 [2] 2e ba [2] 2c bb [2] 37 bd [2] 2b ba [2] 37 95 }

  condition:
    any of them
}