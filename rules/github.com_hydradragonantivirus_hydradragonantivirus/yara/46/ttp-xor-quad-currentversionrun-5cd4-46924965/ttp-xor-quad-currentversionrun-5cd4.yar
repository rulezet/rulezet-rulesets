rule TTP_XOR_QUAD_CurrentVersionRun_5cd4 {
  strings:
    $key_5cd4 = { 0f bb [2] 2b b5 [2] 00 99 [2] 2e bb [2] 3a a0 [2] 35 ba [2] 2b a7 [2] 29 a6 [2] 32 a0 [2] 2e a7 [2] 32 88 }

  condition:
    any of them
}