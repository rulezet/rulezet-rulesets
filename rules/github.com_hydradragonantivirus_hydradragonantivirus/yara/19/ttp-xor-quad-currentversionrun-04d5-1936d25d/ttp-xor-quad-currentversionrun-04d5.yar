rule TTP_XOR_QUAD_CurrentVersionRun_04d5 {
  strings:
    $key_04d5 = { 57 ba [2] 73 b4 [2] 58 98 [2] 76 ba [2] 62 a1 [2] 6d bb [2] 73 a6 [2] 71 a7 [2] 6a a1 [2] 76 a6 [2] 6a 89 }

  condition:
    any of them
}