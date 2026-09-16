rule TTP_XOR_QUAD_CurrentVersionRun_67c7 {
  strings:
    $key_67c7 = { 34 a8 [2] 10 a6 [2] 3b 8a [2] 15 a8 [2] 01 b3 [2] 0e a9 [2] 10 b4 [2] 12 b5 [2] 09 b3 [2] 15 b4 [2] 09 9b }

  condition:
    any of them
}