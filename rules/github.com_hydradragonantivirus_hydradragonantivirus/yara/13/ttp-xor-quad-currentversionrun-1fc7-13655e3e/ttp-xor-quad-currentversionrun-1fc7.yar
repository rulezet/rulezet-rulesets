rule TTP_XOR_QUAD_CurrentVersionRun_1fc7 {
  strings:
    $key_1fc7 = { 4c a8 [2] 68 a6 [2] 43 8a [2] 6d a8 [2] 79 b3 [2] 76 a9 [2] 68 b4 [2] 6a b5 [2] 71 b3 [2] 6d b4 [2] 71 9b }

  condition:
    any of them
}