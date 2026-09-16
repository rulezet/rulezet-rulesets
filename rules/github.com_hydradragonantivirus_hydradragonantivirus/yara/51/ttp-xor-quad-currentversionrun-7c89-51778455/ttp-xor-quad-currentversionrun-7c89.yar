rule TTP_XOR_QUAD_CurrentVersionRun_7c89 {
  strings:
    $key_7c89 = { 2f e6 [2] 0b e8 [2] 20 c4 [2] 0e e6 [2] 1a fd [2] 15 e7 [2] 0b fa [2] 09 fb [2] 12 fd [2] 0e fa [2] 12 d5 }

  condition:
    any of them
}