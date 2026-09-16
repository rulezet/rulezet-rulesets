rule TTP_XOR_QUAD_CurrentVersionRun_4195 {
  strings:
    $key_4195 = { 12 fa [2] 36 f4 [2] 1d d8 [2] 33 fa [2] 27 e1 [2] 28 fb [2] 36 e6 [2] 34 e7 [2] 2f e1 [2] 33 e6 [2] 2f c9 }

  condition:
    any of them
}