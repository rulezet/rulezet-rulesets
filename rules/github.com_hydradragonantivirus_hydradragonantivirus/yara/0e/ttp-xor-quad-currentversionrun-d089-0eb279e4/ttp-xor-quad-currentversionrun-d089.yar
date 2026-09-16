rule TTP_XOR_QUAD_CurrentVersionRun_d089 {
  strings:
    $key_d089 = { 83 e6 [2] a7 e8 [2] 8c c4 [2] a2 e6 [2] b6 fd [2] b9 e7 [2] a7 fa [2] a5 fb [2] be fd [2] a2 fa [2] be d5 }

  condition:
    any of them
}