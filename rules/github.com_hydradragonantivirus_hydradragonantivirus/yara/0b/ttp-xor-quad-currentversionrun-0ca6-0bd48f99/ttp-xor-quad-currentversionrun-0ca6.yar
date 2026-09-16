rule TTP_XOR_QUAD_CurrentVersionRun_0ca6 {
  strings:
    $key_0ca6 = { 5f c9 [2] 7b c7 [2] 50 eb [2] 7e c9 [2] 6a d2 [2] 65 c8 [2] 7b d5 [2] 79 d4 [2] 62 d2 [2] 7e d5 [2] 62 fa }

  condition:
    any of them
}