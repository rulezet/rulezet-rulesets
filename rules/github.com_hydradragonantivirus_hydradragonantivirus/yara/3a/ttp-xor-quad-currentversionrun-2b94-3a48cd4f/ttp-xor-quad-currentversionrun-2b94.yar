rule TTP_XOR_QUAD_CurrentVersionRun_2b94 {
  strings:
    $key_2b94 = { 78 fb [2] 5c f5 [2] 77 d9 [2] 59 fb [2] 4d e0 [2] 42 fa [2] 5c e7 [2] 5e e6 [2] 45 e0 [2] 59 e7 [2] 45 c8 }

  condition:
    any of them
}