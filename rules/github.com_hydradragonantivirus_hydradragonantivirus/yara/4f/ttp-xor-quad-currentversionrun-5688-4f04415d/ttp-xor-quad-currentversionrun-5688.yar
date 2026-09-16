rule TTP_XOR_QUAD_CurrentVersionRun_5688 {
  strings:
    $key_5688 = { 05 e7 [2] 21 e9 [2] 0a c5 [2] 24 e7 [2] 30 fc [2] 3f e6 [2] 21 fb [2] 23 fa [2] 38 fc [2] 24 fb [2] 38 d4 }

  condition:
    any of them
}