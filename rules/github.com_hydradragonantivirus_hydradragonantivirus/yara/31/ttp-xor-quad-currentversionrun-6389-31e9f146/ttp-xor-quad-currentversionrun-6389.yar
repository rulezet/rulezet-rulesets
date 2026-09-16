rule TTP_XOR_QUAD_CurrentVersionRun_6389 {
  strings:
    $key_6389 = { 30 e6 [2] 14 e8 [2] 3f c4 [2] 11 e6 [2] 05 fd [2] 0a e7 [2] 14 fa [2] 16 fb [2] 0d fd [2] 11 fa [2] 0d d5 }

  condition:
    any of them
}