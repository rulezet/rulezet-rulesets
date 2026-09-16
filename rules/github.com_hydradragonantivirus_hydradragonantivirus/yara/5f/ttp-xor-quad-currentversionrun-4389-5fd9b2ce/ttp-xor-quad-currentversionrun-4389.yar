rule TTP_XOR_QUAD_CurrentVersionRun_4389 {
  strings:
    $key_4389 = { 10 e6 [2] 34 e8 [2] 1f c4 [2] 31 e6 [2] 25 fd [2] 2a e7 [2] 34 fa [2] 36 fb [2] 2d fd [2] 31 fa [2] 2d d5 }

  condition:
    any of them
}