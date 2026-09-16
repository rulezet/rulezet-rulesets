rule TTP_XOR_QUAD_CurrentVersionRun_2c89 {
  strings:
    $key_2c89 = { 7f e6 [2] 5b e8 [2] 70 c4 [2] 5e e6 [2] 4a fd [2] 45 e7 [2] 5b fa [2] 59 fb [2] 42 fd [2] 5e fa [2] 42 d5 }

  condition:
    any of them
}