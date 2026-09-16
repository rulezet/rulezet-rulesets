rule TTP_XOR_QUAD_CurrentVersionRun_08d7 {
  strings:
    $key_08d7 = { 5b b8 [2] 7f b6 [2] 54 9a [2] 7a b8 [2] 6e a3 [2] 61 b9 [2] 7f a4 [2] 7d a5 [2] 66 a3 [2] 7a a4 [2] 66 8b }

  condition:
    any of them
}