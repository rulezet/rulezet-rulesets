rule TTP_XOR_QUAD_CurrentVersionRun_0488 {
  strings:
    $key_0488 = { 57 e7 [2] 73 e9 [2] 58 c5 [2] 76 e7 [2] 62 fc [2] 6d e6 [2] 73 fb [2] 71 fa [2] 6a fc [2] 76 fb [2] 6a d4 }

  condition:
    any of them
}