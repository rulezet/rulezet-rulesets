rule TTP_XOR_QUAD_CurrentVersionRun_74a6 {
  strings:
    $key_74a6 = { 27 c9 [2] 03 c7 [2] 28 eb [2] 06 c9 [2] 12 d2 [2] 1d c8 [2] 03 d5 [2] 01 d4 [2] 1a d2 [2] 06 d5 [2] 1a fa }

  condition:
    any of them
}