rule TTP_XOR_QUAD_CurrentVersionRun_28d6 {
  strings:
    $key_28d6 = { 7b b9 [2] 5f b7 [2] 74 9b [2] 5a b9 [2] 4e a2 [2] 41 b8 [2] 5f a5 [2] 5d a4 [2] 46 a2 [2] 5a a5 [2] 46 8a }

  condition:
    any of them
}