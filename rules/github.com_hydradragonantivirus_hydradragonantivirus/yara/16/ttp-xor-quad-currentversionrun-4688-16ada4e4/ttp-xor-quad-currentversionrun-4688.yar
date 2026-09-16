rule TTP_XOR_QUAD_CurrentVersionRun_4688 {
  strings:
    $key_4688 = { 15 e7 [2] 31 e9 [2] 1a c5 [2] 34 e7 [2] 20 fc [2] 2f e6 [2] 31 fb [2] 33 fa [2] 28 fc [2] 34 fb [2] 28 d4 }

  condition:
    any of them
}