rule TTP_XOR_QUAD_CurrentVersionRun_7eb7 {
  strings:
    $key_7eb7 = { 2d d8 [2] 09 d6 [2] 22 fa [2] 0c d8 [2] 18 c3 [2] 17 d9 [2] 09 c4 [2] 0b c5 [2] 10 c3 [2] 0c c4 [2] 10 eb }

  condition:
    any of them
}