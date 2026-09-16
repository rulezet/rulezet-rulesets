rule TTP_XOR_QUAD_CurrentVersionRun_fdd0 {
  strings:
    $key_fdd0 = { ae bf [2] 8a b1 [2] a1 9d [2] 8f bf [2] 9b a4 [2] 94 be [2] 8a a3 [2] 88 a2 [2] 93 a4 [2] 8f a3 [2] 93 8c }

  condition:
    any of them
}