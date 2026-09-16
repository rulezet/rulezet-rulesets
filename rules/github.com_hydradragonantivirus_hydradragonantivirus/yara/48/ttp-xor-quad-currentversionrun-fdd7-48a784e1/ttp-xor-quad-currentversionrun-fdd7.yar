rule TTP_XOR_QUAD_CurrentVersionRun_fdd7 {
  strings:
    $key_fdd7 = { ae b8 [2] 8a b6 [2] a1 9a [2] 8f b8 [2] 9b a3 [2] 94 b9 [2] 8a a4 [2] 88 a5 [2] 93 a3 [2] 8f a4 [2] 93 8b }

  condition:
    any of them
}