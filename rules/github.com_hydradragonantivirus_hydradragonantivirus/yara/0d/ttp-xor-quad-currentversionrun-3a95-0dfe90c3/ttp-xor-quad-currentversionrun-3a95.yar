rule TTP_XOR_QUAD_CurrentVersionRun_3a95 {
  strings:
    $key_3a95 = { 69 fa [2] 4d f4 [2] 66 d8 [2] 48 fa [2] 5c e1 [2] 53 fb [2] 4d e6 [2] 4f e7 [2] 54 e1 [2] 48 e6 [2] 54 c9 }

  condition:
    any of them
}