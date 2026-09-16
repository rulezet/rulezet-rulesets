rule TTP_XOR_QUAD_CurrentVersionRun_5488 {
  strings:
    $key_5488 = { 07 e7 [2] 23 e9 [2] 08 c5 [2] 26 e7 [2] 32 fc [2] 3d e6 [2] 23 fb [2] 21 fa [2] 3a fc [2] 26 fb [2] 3a d4 }

  condition:
    any of them
}