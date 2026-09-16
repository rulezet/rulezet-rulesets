rule TTP_XOR_QUAD_CurrentVersionRun_18c9 {
  strings:
    $key_18c9 = { 4b a6 [2] 6f a8 [2] 44 84 [2] 6a a6 [2] 7e bd [2] 71 a7 [2] 6f ba [2] 6d bb [2] 76 bd [2] 6a ba [2] 76 95 }

  condition:
    any of them
}