rule TTP_XOR_QUAD_CurrentVersionRun_22b7 {
  strings:
    $key_22b7 = { 71 d8 [2] 55 d6 [2] 7e fa [2] 50 d8 [2] 44 c3 [2] 4b d9 [2] 55 c4 [2] 57 c5 [2] 4c c3 [2] 50 c4 [2] 4c eb }

  condition:
    any of them
}