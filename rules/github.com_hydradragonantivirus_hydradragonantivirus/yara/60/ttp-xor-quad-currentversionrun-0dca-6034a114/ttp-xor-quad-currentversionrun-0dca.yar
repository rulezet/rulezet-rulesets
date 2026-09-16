rule TTP_XOR_QUAD_CurrentVersionRun_0dca {
  strings:
    $key_0dca = { 5e a5 [2] 7a ab [2] 51 87 [2] 7f a5 [2] 6b be [2] 64 a4 [2] 7a b9 [2] 78 b8 [2] 63 be [2] 7f b9 [2] 63 96 }

  condition:
    any of them
}