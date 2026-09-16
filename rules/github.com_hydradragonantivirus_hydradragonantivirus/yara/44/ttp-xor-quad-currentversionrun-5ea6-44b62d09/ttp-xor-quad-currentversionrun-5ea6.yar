rule TTP_XOR_QUAD_CurrentVersionRun_5ea6 {
  strings:
    $key_5ea6 = { 0d c9 [2] 29 c7 [2] 02 eb [2] 2c c9 [2] 38 d2 [2] 37 c8 [2] 29 d5 [2] 2b d4 [2] 30 d2 [2] 2c d5 [2] 30 fa }

  condition:
    any of them
}