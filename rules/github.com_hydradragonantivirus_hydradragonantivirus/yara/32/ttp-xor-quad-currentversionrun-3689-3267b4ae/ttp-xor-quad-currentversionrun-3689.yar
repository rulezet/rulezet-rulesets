rule TTP_XOR_QUAD_CurrentVersionRun_3689 {
  strings:
    $key_3689 = { 65 e6 [2] 41 e8 [2] 6a c4 [2] 44 e6 [2] 50 fd [2] 5f e7 [2] 41 fa [2] 43 fb [2] 58 fd [2] 44 fa [2] 58 d5 }

  condition:
    any of them
}