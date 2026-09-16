rule TTP_XOR_QUAD_CurrentVersionRun_eb95 {
  strings:
    $key_eb95 = { b8 fa [2] 9c f4 [2] b7 d8 [2] 99 fa [2] 8d e1 [2] 82 fb [2] 9c e6 [2] 9e e7 [2] 85 e1 [2] 99 e6 [2] 85 c9 }

  condition:
    any of them
}