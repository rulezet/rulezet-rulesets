rule TTP_XOR_QUAD_CurrentVersionRun_02b7 {
  strings:
    $key_02b7 = { 51 d8 [2] 75 d6 [2] 5e fa [2] 70 d8 [2] 64 c3 [2] 6b d9 [2] 75 c4 [2] 77 c5 [2] 6c c3 [2] 70 c4 [2] 6c eb }

  condition:
    any of them
}