rule TTP_XOR_QUAD_CurrentVersionRun_1289 {
  strings:
    $key_1289 = { 41 e6 [2] 65 e8 [2] 4e c4 [2] 60 e6 [2] 74 fd [2] 7b e7 [2] 65 fa [2] 67 fb [2] 7c fd [2] 60 fa [2] 7c d5 }

  condition:
    any of them
}