rule TTP_XOR_QUAD_CurrentVersionRun_7488 {
  strings:
    $key_7488 = { 27 e7 [2] 03 e9 [2] 28 c5 [2] 06 e7 [2] 12 fc [2] 1d e6 [2] 03 fb [2] 01 fa [2] 1a fc [2] 06 fb [2] 1a d4 }

  condition:
    any of them
}