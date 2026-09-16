rule TTP_XOR_QUAD_CurrentVersionRun_7ba6 {
  strings:
    $key_7ba6 = { 28 c9 [2] 0c c7 [2] 27 eb [2] 09 c9 [2] 1d d2 [2] 12 c8 [2] 0c d5 [2] 0e d4 [2] 15 d2 [2] 09 d5 [2] 15 fa }

  condition:
    any of them
}