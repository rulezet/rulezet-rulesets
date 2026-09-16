rule TTP_XOR_QUAD_CurrentVersionRun_7fd4 {
  strings:
    $key_7fd4 = { 2c bb [2] 08 b5 [2] 23 99 [2] 0d bb [2] 19 a0 [2] 16 ba [2] 08 a7 [2] 0a a6 [2] 11 a0 [2] 0d a7 [2] 11 88 }

  condition:
    any of them
}