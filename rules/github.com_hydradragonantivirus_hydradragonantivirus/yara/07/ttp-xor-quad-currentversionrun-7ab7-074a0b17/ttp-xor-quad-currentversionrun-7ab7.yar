rule TTP_XOR_QUAD_CurrentVersionRun_7ab7 {
  strings:
    $key_7ab7 = { 29 d8 [2] 0d d6 [2] 26 fa [2] 08 d8 [2] 1c c3 [2] 13 d9 [2] 0d c4 [2] 0f c5 [2] 14 c3 [2] 08 c4 [2] 14 eb }

  condition:
    any of them
}