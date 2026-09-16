rule TTP_XOR_QUAD_CurrentVersionRun_64d5 {
  strings:
    $key_64d5 = { 37 ba [2] 13 b4 [2] 38 98 [2] 16 ba [2] 02 a1 [2] 0d bb [2] 13 a6 [2] 11 a7 [2] 0a a1 [2] 16 a6 [2] 0a 89 }

  condition:
    any of them
}