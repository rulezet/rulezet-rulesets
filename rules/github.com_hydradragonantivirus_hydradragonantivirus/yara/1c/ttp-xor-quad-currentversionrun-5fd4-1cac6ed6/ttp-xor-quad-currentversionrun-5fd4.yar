rule TTP_XOR_QUAD_CurrentVersionRun_5fd4 {
  strings:
    $key_5fd4 = { 0c bb [2] 28 b5 [2] 03 99 [2] 2d bb [2] 39 a0 [2] 36 ba [2] 28 a7 [2] 2a a6 [2] 31 a0 [2] 2d a7 [2] 31 88 }

  condition:
    any of them
}