rule TTP_XOR_QUAD_CurrentVersionRun_74d5 {
  strings:
    $key_74d5 = { 27 ba [2] 03 b4 [2] 28 98 [2] 06 ba [2] 12 a1 [2] 1d bb [2] 03 a6 [2] 01 a7 [2] 1a a1 [2] 06 a6 [2] 1a 89 }

  condition:
    any of them
}