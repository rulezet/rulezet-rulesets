rule TTP_XOR_QUAD_CurrentVersionRun_3b94 {
  strings:
    $key_3b94 = { 68 fb [2] 4c f5 [2] 67 d9 [2] 49 fb [2] 5d e0 [2] 52 fa [2] 4c e7 [2] 4e e6 [2] 55 e0 [2] 49 e7 [2] 55 c8 }

  condition:
    any of them
}