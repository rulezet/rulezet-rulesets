rule TTP_XOR_QUAD_CurrentVersionRun_36a6 {
  strings:
    $key_36a6 = { 65 c9 [2] 41 c7 [2] 6a eb [2] 44 c9 [2] 50 d2 [2] 5f c8 [2] 41 d5 [2] 43 d4 [2] 58 d2 [2] 44 d5 [2] 58 fa }

  condition:
    any of them
}