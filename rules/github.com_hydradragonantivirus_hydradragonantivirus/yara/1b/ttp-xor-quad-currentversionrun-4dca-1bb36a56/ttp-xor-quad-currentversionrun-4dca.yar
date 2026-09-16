rule TTP_XOR_QUAD_CurrentVersionRun_4dca {
  strings:
    $key_4dca = { 1e a5 [2] 3a ab [2] 11 87 [2] 3f a5 [2] 2b be [2] 24 a4 [2] 3a b9 [2] 38 b8 [2] 23 be [2] 3f b9 [2] 23 96 }

  condition:
    any of them
}