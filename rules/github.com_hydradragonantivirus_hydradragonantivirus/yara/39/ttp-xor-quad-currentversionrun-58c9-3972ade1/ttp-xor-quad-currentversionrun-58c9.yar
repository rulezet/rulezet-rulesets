rule TTP_XOR_QUAD_CurrentVersionRun_58c9 {
  strings:
    $key_58c9 = { 0b a6 [2] 2f a8 [2] 04 84 [2] 2a a6 [2] 3e bd [2] 31 a7 [2] 2f ba [2] 2d bb [2] 36 bd [2] 2a ba [2] 36 95 }

  condition:
    any of them
}