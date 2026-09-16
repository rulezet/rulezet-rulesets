rule TTP_XOR_QUAD_CurrentVersionRun_6195 {
  strings:
    $key_6195 = { 32 fa [2] 16 f4 [2] 3d d8 [2] 13 fa [2] 07 e1 [2] 08 fb [2] 16 e6 [2] 14 e7 [2] 0f e1 [2] 13 e6 [2] 0f c9 }

  condition:
    any of them
}