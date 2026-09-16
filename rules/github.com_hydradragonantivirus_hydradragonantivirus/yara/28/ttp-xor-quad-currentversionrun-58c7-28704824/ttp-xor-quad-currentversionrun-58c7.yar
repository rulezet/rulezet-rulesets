rule TTP_XOR_QUAD_CurrentVersionRun_58c7 {
  strings:
    $key_58c7 = { 0b a8 [2] 2f a6 [2] 04 8a [2] 2a a8 [2] 3e b3 [2] 31 a9 [2] 2f b4 [2] 2d b5 [2] 36 b3 [2] 2a b4 [2] 36 9b }

  condition:
    any of them
}