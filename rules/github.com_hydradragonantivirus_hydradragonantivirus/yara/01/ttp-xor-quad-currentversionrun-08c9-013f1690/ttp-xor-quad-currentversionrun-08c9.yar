rule TTP_XOR_QUAD_CurrentVersionRun_08c9 {
  strings:
    $key_08c9 = { 5b a6 [2] 7f a8 [2] 54 84 [2] 7a a6 [2] 6e bd [2] 61 a7 [2] 7f ba [2] 7d bb [2] 66 bd [2] 7a ba [2] 66 95 }

  condition:
    any of them
}