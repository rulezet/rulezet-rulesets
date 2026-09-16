rule TTP_XOR_QUAD_CurrentVersionRun_2dd7 {
  strings:
    $key_2dd7 = { 7e b8 [2] 5a b6 [2] 71 9a [2] 5f b8 [2] 4b a3 [2] 44 b9 [2] 5a a4 [2] 58 a5 [2] 43 a3 [2] 5f a4 [2] 43 8b }

  condition:
    any of them
}