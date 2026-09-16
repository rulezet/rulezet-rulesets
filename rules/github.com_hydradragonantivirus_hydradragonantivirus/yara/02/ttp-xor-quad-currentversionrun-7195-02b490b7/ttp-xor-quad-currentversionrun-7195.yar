rule TTP_XOR_QUAD_CurrentVersionRun_7195 {
  strings:
    $key_7195 = { 22 fa [2] 06 f4 [2] 2d d8 [2] 03 fa [2] 17 e1 [2] 18 fb [2] 06 e6 [2] 04 e7 [2] 1f e1 [2] 03 e6 [2] 1f c9 }

  condition:
    any of them
}