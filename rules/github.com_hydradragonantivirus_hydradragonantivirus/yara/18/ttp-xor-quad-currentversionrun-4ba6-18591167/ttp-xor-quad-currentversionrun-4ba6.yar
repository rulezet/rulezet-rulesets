rule TTP_XOR_QUAD_CurrentVersionRun_4ba6 {
  strings:
    $key_4ba6 = { 18 c9 [2] 3c c7 [2] 17 eb [2] 39 c9 [2] 2d d2 [2] 22 c8 [2] 3c d5 [2] 3e d4 [2] 25 d2 [2] 39 d5 [2] 25 fa }

  condition:
    any of them
}