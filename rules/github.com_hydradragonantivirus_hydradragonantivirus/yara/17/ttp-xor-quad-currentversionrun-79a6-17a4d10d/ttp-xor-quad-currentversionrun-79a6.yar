rule TTP_XOR_QUAD_CurrentVersionRun_79a6 {
  strings:
    $key_79a6 = { 2a c9 [2] 0e c7 [2] 25 eb [2] 0b c9 [2] 1f d2 [2] 10 c8 [2] 0e d5 [2] 0c d4 [2] 17 d2 [2] 0b d5 [2] 17 fa }

  condition:
    any of them
}