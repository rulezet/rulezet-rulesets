rule TTP_XOR_QUAD_CurrentVersionRun_1195 {
  strings:
    $key_1195 = { 42 fa [2] 66 f4 [2] 4d d8 [2] 63 fa [2] 77 e1 [2] 78 fb [2] 66 e6 [2] 64 e7 [2] 7f e1 [2] 63 e6 [2] 7f c9 }

  condition:
    any of them
}