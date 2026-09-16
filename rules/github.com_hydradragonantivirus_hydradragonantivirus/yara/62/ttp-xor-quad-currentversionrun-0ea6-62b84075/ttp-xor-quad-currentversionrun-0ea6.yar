rule TTP_XOR_QUAD_CurrentVersionRun_0ea6 {
  strings:
    $key_0ea6 = { 5d c9 [2] 79 c7 [2] 52 eb [2] 7c c9 [2] 68 d2 [2] 67 c8 [2] 79 d5 [2] 7b d4 [2] 60 d2 [2] 7c d5 [2] 60 fa }

  condition:
    any of them
}