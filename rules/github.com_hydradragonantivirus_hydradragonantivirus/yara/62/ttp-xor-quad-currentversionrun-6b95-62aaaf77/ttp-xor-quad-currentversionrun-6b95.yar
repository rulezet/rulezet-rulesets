rule TTP_XOR_QUAD_CurrentVersionRun_6b95 {
  strings:
    $key_6b95 = { 38 fa [2] 1c f4 [2] 37 d8 [2] 19 fa [2] 0d e1 [2] 02 fb [2] 1c e6 [2] 1e e7 [2] 05 e1 [2] 19 e6 [2] 05 c9 }

  condition:
    any of them
}