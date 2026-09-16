rule TTP_XOR_QUAD_CurrentVersionRun_7ea6 {
  strings:
    $key_7ea6 = { 2d c9 [2] 09 c7 [2] 22 eb [2] 0c c9 [2] 18 d2 [2] 17 c8 [2] 09 d5 [2] 0b d4 [2] 10 d2 [2] 0c d5 [2] 10 fa }

  condition:
    any of them
}