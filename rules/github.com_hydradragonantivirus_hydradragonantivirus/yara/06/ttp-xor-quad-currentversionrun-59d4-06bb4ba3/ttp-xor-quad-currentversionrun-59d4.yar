rule TTP_XOR_QUAD_CurrentVersionRun_59d4 {
  strings:
    $key_59d4 = { 0a bb [2] 2e b5 [2] 05 99 [2] 2b bb [2] 3f a0 [2] 30 ba [2] 2e a7 [2] 2c a6 [2] 37 a0 [2] 2b a7 [2] 37 88 }

  condition:
    any of them
}