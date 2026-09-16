rule TTP_XOR_QUAD_CurrentVersionRun_18c6 {
  strings:
    $key_18c6 = { 4b a9 [2] 6f a7 [2] 44 8b [2] 6a a9 [2] 7e b2 [2] 71 a8 [2] 6f b5 [2] 6d b4 [2] 76 b2 [2] 6a b5 [2] 76 9a }

  condition:
    any of them
}