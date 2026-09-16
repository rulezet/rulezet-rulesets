rule TTP_XOR_QUAD_CurrentVersionRun_15b7 {
  strings:
    $key_15b7 = { 46 d8 [2] 62 d6 [2] 49 fa [2] 67 d8 [2] 73 c3 [2] 7c d9 [2] 62 c4 [2] 60 c5 [2] 7b c3 [2] 67 c4 [2] 7b eb }

  condition:
    any of them
}