rule TTP_XOR_QUAD_CurrentVersionRun_2288 {
  strings:
    $key_2288 = { 71 e7 [2] 55 e9 [2] 7e c5 [2] 50 e7 [2] 44 fc [2] 4b e6 [2] 55 fb [2] 57 fa [2] 4c fc [2] 50 fb [2] 4c d4 }

  condition:
    any of them
}