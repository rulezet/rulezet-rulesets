rule TTP_XOR_QUAD_CurrentVersionRun_3789 {
  strings:
    $key_3789 = { 64 e6 [2] 40 e8 [2] 6b c4 [2] 45 e6 [2] 51 fd [2] 5e e7 [2] 40 fa [2] 42 fb [2] 59 fd [2] 45 fa [2] 59 d5 }

  condition:
    any of them
}