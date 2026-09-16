rule TTP_XOR_QUAD_CurrentVersionRun_2dc6 {
  strings:
    $key_2dc6 = { 7e a9 [2] 5a a7 [2] 71 8b [2] 5f a9 [2] 4b b2 [2] 44 a8 [2] 5a b5 [2] 58 b4 [2] 43 b2 [2] 5f b5 [2] 43 9a }

  condition:
    any of them
}