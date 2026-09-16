rule TTP_XOR_QUAD_CurrentVersionRun_0ba6 {
  strings:
    $key_0ba6 = { 58 c9 [2] 7c c7 [2] 57 eb [2] 79 c9 [2] 6d d2 [2] 62 c8 [2] 7c d5 [2] 7e d4 [2] 65 d2 [2] 79 d5 [2] 65 fa }

  condition:
    any of them
}