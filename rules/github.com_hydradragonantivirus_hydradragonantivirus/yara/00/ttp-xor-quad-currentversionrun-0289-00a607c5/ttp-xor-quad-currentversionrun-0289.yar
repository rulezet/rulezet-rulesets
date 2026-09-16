rule TTP_XOR_QUAD_CurrentVersionRun_0289 {
  strings:
    $key_0289 = { 51 e6 [2] 75 e8 [2] 5e c4 [2] 70 e6 [2] 64 fd [2] 6b e7 [2] 75 fa [2] 77 fb [2] 6c fd [2] 70 fa [2] 6c d5 }

  condition:
    any of them
}