rule TTP_XOR_QUAD_CurrentVersionRun_ea95 {
  strings:
    $key_ea95 = { b9 fa [2] 9d f4 [2] b6 d8 [2] 98 fa [2] 8c e1 [2] 83 fb [2] 9d e6 [2] 9f e7 [2] 84 e1 [2] 98 e6 [2] 84 c9 }

  condition:
    any of them
}