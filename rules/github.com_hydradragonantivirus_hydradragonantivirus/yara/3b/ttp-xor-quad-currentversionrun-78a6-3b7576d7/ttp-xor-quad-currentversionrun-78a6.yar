rule TTP_XOR_QUAD_CurrentVersionRun_78a6 {
  strings:
    $key_78a6 = { 2b c9 [2] 0f c7 [2] 24 eb [2] 0a c9 [2] 1e d2 [2] 11 c8 [2] 0f d5 [2] 0d d4 [2] 16 d2 [2] 0a d5 [2] 16 fa }

  condition:
    any of them
}