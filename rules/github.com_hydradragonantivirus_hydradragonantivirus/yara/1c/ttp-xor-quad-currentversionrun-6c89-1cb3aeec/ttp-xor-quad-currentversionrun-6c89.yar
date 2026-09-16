rule TTP_XOR_QUAD_CurrentVersionRun_6c89 {
  strings:
    $key_6c89 = { 3f e6 [2] 1b e8 [2] 30 c4 [2] 1e e6 [2] 0a fd [2] 05 e7 [2] 1b fa [2] 19 fb [2] 02 fd [2] 1e fa [2] 02 d5 }

  condition:
    any of them
}