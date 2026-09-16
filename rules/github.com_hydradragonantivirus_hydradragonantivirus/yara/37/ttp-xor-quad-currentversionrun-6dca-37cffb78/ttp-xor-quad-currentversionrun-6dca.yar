rule TTP_XOR_QUAD_CurrentVersionRun_6dca {
  strings:
    $key_6dca = { 3e a5 [2] 1a ab [2] 31 87 [2] 1f a5 [2] 0b be [2] 04 a4 [2] 1a b9 [2] 18 b8 [2] 03 be [2] 1f b9 [2] 03 96 }

  condition:
    any of them
}