rule TTP_XOR_QUAD_CurrentVersionRun_1fb7 {
  strings:
    $key_1fb7 = { 4c d8 [2] 68 d6 [2] 43 fa [2] 6d d8 [2] 79 c3 [2] 76 d9 [2] 68 c4 [2] 6a c5 [2] 71 c3 [2] 6d c4 [2] 71 eb }

  condition:
    any of them
}