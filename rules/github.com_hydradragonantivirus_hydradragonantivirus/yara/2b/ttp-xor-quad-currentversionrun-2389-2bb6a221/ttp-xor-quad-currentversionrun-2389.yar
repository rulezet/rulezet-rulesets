rule TTP_XOR_QUAD_CurrentVersionRun_2389 {
  strings:
    $key_2389 = { 70 e6 [2] 54 e8 [2] 7f c4 [2] 51 e6 [2] 45 fd [2] 4a e7 [2] 54 fa [2] 56 fb [2] 4d fd [2] 51 fa [2] 4d d5 }

  condition:
    any of them
}