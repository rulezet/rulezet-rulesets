rule TTP_XOR_QUAD_CurrentVersionRun_e8c6 {
  strings:
    $key_e8c6 = { bb a9 [2] 9f a7 [2] b4 8b [2] 9a a9 [2] 8e b2 [2] 81 a8 [2] 9f b5 [2] 9d b4 [2] 86 b2 [2] 9a b5 [2] 86 9a }

  condition:
    any of them
}