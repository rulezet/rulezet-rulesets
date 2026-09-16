rule TTP_XOR_QUAD_CurrentVersionRun_f494 {
  strings:
    $key_f494 = { a7 fb [2] 83 f5 [2] a8 d9 [2] 86 fb [2] 92 e0 [2] 9d fa [2] 83 e7 [2] 81 e6 [2] 9a e0 [2] 86 e7 [2] 9a c8 }

  condition:
    any of them
}