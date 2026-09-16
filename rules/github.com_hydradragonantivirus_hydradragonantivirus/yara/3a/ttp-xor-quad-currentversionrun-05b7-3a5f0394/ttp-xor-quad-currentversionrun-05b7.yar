rule TTP_XOR_QUAD_CurrentVersionRun_05b7 {
  strings:
    $key_05b7 = { 56 d8 [2] 72 d6 [2] 59 fa [2] 77 d8 [2] 63 c3 [2] 6c d9 [2] 72 c4 [2] 70 c5 [2] 6b c3 [2] 77 c4 [2] 6b eb }

  condition:
    any of them
}