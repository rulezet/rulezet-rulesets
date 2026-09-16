rule TTP_XOR_QUAD_CurrentVersionRun_3389 {
  strings:
    $key_3389 = { 60 e6 [2] 44 e8 [2] 6f c4 [2] 41 e6 [2] 55 fd [2] 5a e7 [2] 44 fa [2] 46 fb [2] 5d fd [2] 41 fa [2] 5d d5 }

  condition:
    any of them
}