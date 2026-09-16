rule TTP_XOR_QUAD_CurrentVersionRun_38c7 {
  strings:
    $key_38c7 = { 6b a8 [2] 4f a6 [2] 64 8a [2] 4a a8 [2] 5e b3 [2] 51 a9 [2] 4f b4 [2] 4d b5 [2] 56 b3 [2] 4a b4 [2] 56 9b }

  condition:
    any of them
}