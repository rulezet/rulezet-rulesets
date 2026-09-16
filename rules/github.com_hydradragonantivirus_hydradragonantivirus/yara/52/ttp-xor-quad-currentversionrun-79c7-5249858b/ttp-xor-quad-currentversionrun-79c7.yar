rule TTP_XOR_QUAD_CurrentVersionRun_79c7 {
  strings:
    $key_79c7 = { 2a a8 [2] 0e a6 [2] 25 8a [2] 0b a8 [2] 1f b3 [2] 10 a9 [2] 0e b4 [2] 0c b5 [2] 17 b3 [2] 0b b4 [2] 17 9b }

  condition:
    any of them
}