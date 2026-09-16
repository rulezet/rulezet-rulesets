rule TTP_XOR_QUAD_CurrentVersionRun_4ea6 {
  strings:
    $key_4ea6 = { 1d c9 [2] 39 c7 [2] 12 eb [2] 3c c9 [2] 28 d2 [2] 27 c8 [2] 39 d5 [2] 3b d4 [2] 20 d2 [2] 3c d5 [2] 20 fa }

  condition:
    any of them
}