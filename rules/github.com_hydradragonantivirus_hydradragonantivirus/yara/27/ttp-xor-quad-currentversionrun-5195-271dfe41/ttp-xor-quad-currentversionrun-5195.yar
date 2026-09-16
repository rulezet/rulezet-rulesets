rule TTP_XOR_QUAD_CurrentVersionRun_5195 {
  strings:
    $key_5195 = { 02 fa [2] 26 f4 [2] 0d d8 [2] 23 fa [2] 37 e1 [2] 38 fb [2] 26 e6 [2] 24 e7 [2] 3f e1 [2] 23 e6 [2] 3f c9 }

  condition:
    any of them
}