rule TTP_XOR_QUAD_CurrentVersionRun_1389 {
  strings:
    $key_1389 = { 40 e6 [2] 64 e8 [2] 4f c4 [2] 61 e6 [2] 75 fd [2] 7a e7 [2] 64 fa [2] 66 fb [2] 7d fd [2] 61 fa [2] 7d d5 }

  condition:
    any of them
}