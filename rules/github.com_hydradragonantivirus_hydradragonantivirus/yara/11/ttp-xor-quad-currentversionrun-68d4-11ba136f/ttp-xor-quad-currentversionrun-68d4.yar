rule TTP_XOR_QUAD_CurrentVersionRun_68d4 {
  strings:
    $key_68d4 = { 3b bb [2] 1f b5 [2] 34 99 [2] 1a bb [2] 0e a0 [2] 01 ba [2] 1f a7 [2] 1d a6 [2] 06 a0 [2] 1a a7 [2] 06 88 }

  condition:
    any of them
}