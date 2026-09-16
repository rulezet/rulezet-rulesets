rule TTP_XOR_QUAD_CurrentVersionRun_fdc7 {
  strings:
    $key_fdc7 = { ae a8 [2] 8a a6 [2] a1 8a [2] 8f a8 [2] 9b b3 [2] 94 a9 [2] 8a b4 [2] 88 b5 [2] 93 b3 [2] 8f b4 [2] 93 9b }

  condition:
    any of them
}