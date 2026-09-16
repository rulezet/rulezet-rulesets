rule TTP_XOR_QUAD_CurrentVersionRun_64a6 {
  strings:
    $key_64a6 = { 37 c9 [2] 13 c7 [2] 38 eb [2] 16 c9 [2] 02 d2 [2] 0d c8 [2] 13 d5 [2] 11 d4 [2] 0a d2 [2] 16 d5 [2] 0a fa }

  condition:
    any of them
}