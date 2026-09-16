rule TTP_XOR_QUAD_CurrentVersionRun_5489 {
  strings:
    $key_5489 = { 07 e6 [2] 23 e8 [2] 08 c4 [2] 26 e6 [2] 32 fd [2] 3d e7 [2] 23 fa [2] 21 fb [2] 3a fd [2] 26 fa [2] 3a d5 }

  condition:
    any of them
}