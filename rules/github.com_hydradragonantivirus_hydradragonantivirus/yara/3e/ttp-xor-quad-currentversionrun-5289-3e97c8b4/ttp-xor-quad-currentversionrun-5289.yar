rule TTP_XOR_QUAD_CurrentVersionRun_5289 {
  strings:
    $key_5289 = { 01 e6 [2] 25 e8 [2] 0e c4 [2] 20 e6 [2] 34 fd [2] 3b e7 [2] 25 fa [2] 27 fb [2] 3c fd [2] 20 fa [2] 3c d5 }

  condition:
    any of them
}