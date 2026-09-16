rule TTP_XOR_QUAD_CurrentVersionRun_4dd7 {
  strings:
    $key_4dd7 = { 1e b8 [2] 3a b6 [2] 11 9a [2] 3f b8 [2] 2b a3 [2] 24 b9 [2] 3a a4 [2] 38 a5 [2] 23 a3 [2] 3f a4 [2] 23 8b }

  condition:
    any of them
}