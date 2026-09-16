rule TTP_XOR_QUAD_CurrentVersionRun_fdca {
  strings:
    $key_fdca = { ae a5 [2] 8a ab [2] a1 87 [2] 8f a5 [2] 9b be [2] 94 a4 [2] 8a b9 [2] 88 b8 [2] 93 be [2] 8f b9 [2] 93 96 }

  condition:
    any of them
}