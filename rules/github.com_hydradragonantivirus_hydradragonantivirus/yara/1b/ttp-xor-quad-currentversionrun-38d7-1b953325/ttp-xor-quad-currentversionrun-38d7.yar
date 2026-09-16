rule TTP_XOR_QUAD_CurrentVersionRun_38d7 {
  strings:
    $key_38d7 = { 6b b8 [2] 4f b6 [2] 64 9a [2] 4a b8 [2] 5e a3 [2] 51 b9 [2] 4f a4 [2] 4d a5 [2] 56 a3 [2] 4a a4 [2] 56 8b }

  condition:
    any of them
}