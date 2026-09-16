rule TTP_XOR_QUAD_CurrentVersionRun_5dd4 {
  strings:
    $key_5dd4 = { 0e bb [2] 2a b5 [2] 01 99 [2] 2f bb [2] 3b a0 [2] 34 ba [2] 2a a7 [2] 28 a6 [2] 33 a0 [2] 2f a7 [2] 33 88 }

  condition:
    any of them
}