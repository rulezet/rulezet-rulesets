rule TTP_XOR_QUAD_CurrentVersionRun_2dca {
  strings:
    $key_2dca = { 7e a5 [2] 5a ab [2] 71 87 [2] 5f a5 [2] 4b be [2] 44 a4 [2] 5a b9 [2] 58 b8 [2] 43 be [2] 5f b9 [2] 43 96 }

  condition:
    any of them
}