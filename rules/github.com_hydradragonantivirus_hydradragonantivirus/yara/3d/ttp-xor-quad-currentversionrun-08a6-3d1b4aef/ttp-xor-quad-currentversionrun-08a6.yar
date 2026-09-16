rule TTP_XOR_QUAD_CurrentVersionRun_08a6 {
  strings:
    $key_08a6 = { 5b c9 [2] 7f c7 [2] 54 eb [2] 7a c9 [2] 6e d2 [2] 61 c8 [2] 7f d5 [2] 7d d4 [2] 66 d2 [2] 7a d5 [2] 66 fa }

  condition:
    any of them
}