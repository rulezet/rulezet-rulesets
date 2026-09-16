rule TTP_XOR_QUAD_CurrentVersionRun_7dca {
  strings:
    $key_7dca = { 2e a5 [2] 0a ab [2] 21 87 [2] 0f a5 [2] 1b be [2] 14 a4 [2] 0a b9 [2] 08 b8 [2] 13 be [2] 0f b9 [2] 13 96 }

  condition:
    any of them
}