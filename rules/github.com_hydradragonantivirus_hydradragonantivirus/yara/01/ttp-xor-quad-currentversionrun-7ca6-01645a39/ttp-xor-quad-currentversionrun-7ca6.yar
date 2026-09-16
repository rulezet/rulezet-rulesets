rule TTP_XOR_QUAD_CurrentVersionRun_7ca6 {
  strings:
    $key_7ca6 = { 2f c9 [2] 0b c7 [2] 20 eb [2] 0e c9 [2] 1a d2 [2] 15 c8 [2] 0b d5 [2] 09 d4 [2] 12 d2 [2] 0e d5 [2] 12 fa }

  condition:
    any of them
}