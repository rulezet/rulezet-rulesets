rule TTP_XOR_QUAD_CurrentVersionRun_fdc6 {
  strings:
    $key_fdc6 = { ae a9 [2] 8a a7 [2] a1 8b [2] 8f a9 [2] 9b b2 [2] 94 a8 [2] 8a b5 [2] 88 b4 [2] 93 b2 [2] 8f b5 [2] 93 9a }

  condition:
    any of them
}