rule TTP_XOR_QUAD_CurrentVersionRun_60a6 {
  strings:
    $key_60a6 = { 33 c9 [2] 17 c7 [2] 3c eb [2] 12 c9 [2] 06 d2 [2] 09 c8 [2] 17 d5 [2] 15 d4 [2] 0e d2 [2] 12 d5 [2] 0e fa }

  condition:
    any of them
}