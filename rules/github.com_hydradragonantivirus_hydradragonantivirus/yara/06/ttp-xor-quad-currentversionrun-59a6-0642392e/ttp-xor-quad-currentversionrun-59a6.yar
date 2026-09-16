rule TTP_XOR_QUAD_CurrentVersionRun_59a6 {
  strings:
    $key_59a6 = { 0a c9 [2] 2e c7 [2] 05 eb [2] 2b c9 [2] 3f d2 [2] 30 c8 [2] 2e d5 [2] 2c d4 [2] 37 d2 [2] 2b d5 [2] 37 fa }

  condition:
    any of them
}