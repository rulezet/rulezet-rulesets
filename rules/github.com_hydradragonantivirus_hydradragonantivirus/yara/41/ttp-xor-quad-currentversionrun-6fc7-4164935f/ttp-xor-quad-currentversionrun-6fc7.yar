rule TTP_XOR_QUAD_CurrentVersionRun_6fc7 {
  strings:
    $key_6fc7 = { 3c a8 [2] 18 a6 [2] 33 8a [2] 1d a8 [2] 09 b3 [2] 06 a9 [2] 18 b4 [2] 1a b5 [2] 01 b3 [2] 1d b4 [2] 01 9b }

  condition:
    any of them
}