rule TTP_XOR_QUAD_CurrentVersionRun_1dca {
  strings:
    $key_1dca = { 4e a5 [2] 6a ab [2] 41 87 [2] 6f a5 [2] 7b be [2] 74 a4 [2] 6a b9 [2] 68 b8 [2] 73 be [2] 6f b9 [2] 73 96 }

  condition:
    any of them
}