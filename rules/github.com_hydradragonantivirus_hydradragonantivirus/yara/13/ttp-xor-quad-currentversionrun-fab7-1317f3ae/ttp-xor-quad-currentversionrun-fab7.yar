rule TTP_XOR_QUAD_CurrentVersionRun_fab7 {
  strings:
    $key_fab7 = { a9 d8 [2] 8d d6 [2] a6 fa [2] 88 d8 [2] 9c c3 [2] 93 d9 [2] 8d c4 [2] 8f c5 [2] 94 c3 [2] 88 c4 [2] 94 eb }

  condition:
    any of them
}