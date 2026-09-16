rule TTP_XOR_QUAD_CurrentVersionRun_64d4 {
  strings:
    $key_64d4 = { 37 bb [2] 13 b5 [2] 38 99 [2] 16 bb [2] 02 a0 [2] 0d ba [2] 13 a7 [2] 11 a6 [2] 0a a0 [2] 16 a7 [2] 0a 88 }

  condition:
    any of them
}