rule TTP_XOR_QUAD_CurrentVersionRun_4eb7 {
  strings:
    $key_4eb7 = { 1d d8 [2] 39 d6 [2] 12 fa [2] 3c d8 [2] 28 c3 [2] 27 d9 [2] 39 c4 [2] 3b c5 [2] 20 c3 [2] 3c c4 [2] 20 eb }

  condition:
    any of them
}