rule TTP_XOR_QUAD_CurrentVersionRun_4194 {
  strings:
    $key_4194 = { 12 fb [2] 36 f5 [2] 1d d9 [2] 33 fb [2] 27 e0 [2] 28 fa [2] 36 e7 [2] 34 e6 [2] 2f e0 [2] 33 e7 [2] 2f c8 }

  condition:
    any of them
}