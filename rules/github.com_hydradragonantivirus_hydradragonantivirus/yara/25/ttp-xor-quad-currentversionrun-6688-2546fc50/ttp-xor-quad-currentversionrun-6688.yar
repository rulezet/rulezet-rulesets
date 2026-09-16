rule TTP_XOR_QUAD_CurrentVersionRun_6688 {
  strings:
    $key_6688 = { 35 e7 [2] 11 e9 [2] 3a c5 [2] 14 e7 [2] 00 fc [2] 0f e6 [2] 11 fb [2] 13 fa [2] 08 fc [2] 14 fb [2] 08 d4 }

  condition:
    any of them
}