rule TTP_XOR_QUAD_CurrentVersionRun_2fc7 {
  strings:
    $key_2fc7 = { 7c a8 [2] 58 a6 [2] 73 8a [2] 5d a8 [2] 49 b3 [2] 46 a9 [2] 58 b4 [2] 5a b5 [2] 41 b3 [2] 5d b4 [2] 41 9b }

  condition:
    any of them
}