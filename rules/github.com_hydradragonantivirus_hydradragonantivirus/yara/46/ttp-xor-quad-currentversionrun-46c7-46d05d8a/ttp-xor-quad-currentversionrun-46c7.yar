rule TTP_XOR_QUAD_CurrentVersionRun_46c7 {
  strings:
    $key_46c7 = { 15 a8 [2] 31 a6 [2] 1a 8a [2] 34 a8 [2] 20 b3 [2] 2f a9 [2] 31 b4 [2] 33 b5 [2] 28 b3 [2] 34 b4 [2] 28 9b }

  condition:
    any of them
}