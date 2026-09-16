rule TTP_XOR_QUAD_CurrentVersionRun_0dd4 {
  strings:
    $key_0dd4 = { 5e bb [2] 7a b5 [2] 51 99 [2] 7f bb [2] 6b a0 [2] 64 ba [2] 7a a7 [2] 78 a6 [2] 63 a0 [2] 7f a7 [2] 63 88 }

  condition:
    any of them
}