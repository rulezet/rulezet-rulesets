rule TTP_XOR_QUAD_CurrentVersionRun_2289 {
  strings:
    $key_2289 = { 71 e6 [2] 55 e8 [2] 7e c4 [2] 50 e6 [2] 44 fd [2] 4b e7 [2] 55 fa [2] 57 fb [2] 4c fd [2] 50 fa [2] 4c d5 }

  condition:
    any of them
}