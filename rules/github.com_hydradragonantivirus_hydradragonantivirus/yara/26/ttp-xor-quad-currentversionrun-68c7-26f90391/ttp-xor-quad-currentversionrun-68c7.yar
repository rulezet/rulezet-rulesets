rule TTP_XOR_QUAD_CurrentVersionRun_68c7 {
  strings:
    $key_68c7 = { 3b a8 [2] 1f a6 [2] 34 8a [2] 1a a8 [2] 0e b3 [2] 01 a9 [2] 1f b4 [2] 1d b5 [2] 06 b3 [2] 1a b4 [2] 06 9b }

  condition:
    any of them
}