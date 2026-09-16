rule TTP_XOR_QUAD_CurrentVersionRun_7cd4 {
  strings:
    $key_7cd4 = { 2f bb [2] 0b b5 [2] 20 99 [2] 0e bb [2] 1a a0 [2] 15 ba [2] 0b a7 [2] 09 a6 [2] 12 a0 [2] 0e a7 [2] 12 88 }

  condition:
    any of them
}