rule TTP_XOR_QUAD_CurrentVersionRun_0cd4 {
  strings:
    $key_0cd4 = { 5f bb [2] 7b b5 [2] 50 99 [2] 7e bb [2] 6a a0 [2] 65 ba [2] 7b a7 [2] 79 a6 [2] 62 a0 [2] 7e a7 [2] 62 88 }

  condition:
    any of them
}