rule TTP_XOR_QUAD_CurrentVersionRun_79d4 {
  strings:
    $key_79d4 = { 2a bb [2] 0e b5 [2] 25 99 [2] 0b bb [2] 1f a0 [2] 10 ba [2] 0e a7 [2] 0c a6 [2] 17 a0 [2] 0b a7 [2] 17 88 }

  condition:
    any of them
}