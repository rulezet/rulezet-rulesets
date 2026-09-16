rule TTP_XOR_QUAD_CurrentVersionRun_f689 {
  strings:
    $key_f689 = { a5 e6 [2] 81 e8 [2] aa c4 [2] 84 e6 [2] 90 fd [2] 9f e7 [2] 81 fa [2] 83 fb [2] 98 fd [2] 84 fa [2] 98 d5 }

  condition:
    any of them
}