rule TTP_XOR_QUAD_CurrentVersionRun_12b7 {
  strings:
    $key_12b7 = { 41 d8 [2] 65 d6 [2] 4e fa [2] 60 d8 [2] 74 c3 [2] 7b d9 [2] 65 c4 [2] 67 c5 [2] 7c c3 [2] 60 c4 [2] 7c eb }

  condition:
    any of them
}