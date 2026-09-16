rule TTP_XOR_QUAD_CurrentVersionRun_7dd4 {
  strings:
    $key_7dd4 = { 2e bb [2] 0a b5 [2] 21 99 [2] 0f bb [2] 1b a0 [2] 14 ba [2] 0a a7 [2] 08 a6 [2] 13 a0 [2] 0f a7 [2] 13 88 }

  condition:
    any of them
}