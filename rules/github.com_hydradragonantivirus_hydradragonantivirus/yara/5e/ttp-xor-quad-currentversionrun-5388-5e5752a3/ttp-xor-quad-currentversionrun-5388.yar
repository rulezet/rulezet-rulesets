rule TTP_XOR_QUAD_CurrentVersionRun_5388 {
  strings:
    $key_5388 = { 00 e7 [2] 24 e9 [2] 0f c5 [2] 21 e7 [2] 35 fc [2] 3a e6 [2] 24 fb [2] 26 fa [2] 3d fc [2] 21 fb [2] 3d d4 }

  condition:
    any of them
}