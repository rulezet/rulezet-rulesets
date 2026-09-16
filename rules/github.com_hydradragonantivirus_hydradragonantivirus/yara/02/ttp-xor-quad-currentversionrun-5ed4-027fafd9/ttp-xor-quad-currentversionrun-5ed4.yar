rule TTP_XOR_QUAD_CurrentVersionRun_5ed4 {
  strings:
    $key_5ed4 = { 0d bb [2] 29 b5 [2] 02 99 [2] 2c bb [2] 38 a0 [2] 37 ba [2] 29 a7 [2] 2b a6 [2] 30 a0 [2] 2c a7 [2] 30 88 }

  condition:
    any of them
}