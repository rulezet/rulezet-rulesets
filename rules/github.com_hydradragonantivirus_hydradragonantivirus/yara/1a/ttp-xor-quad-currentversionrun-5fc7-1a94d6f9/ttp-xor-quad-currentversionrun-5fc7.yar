rule TTP_XOR_QUAD_CurrentVersionRun_5fc7 {
  strings:
    $key_5fc7 = { 0c a8 [2] 28 a6 [2] 03 8a [2] 2d a8 [2] 39 b3 [2] 36 a9 [2] 28 b4 [2] 2a b5 [2] 31 b3 [2] 2d b4 [2] 31 9b }

  condition:
    any of them
}