rule TTP_XOR_QUAD_CurrentVersionRun_c089 {
  strings:
    $key_c089 = { 93 e6 [2] b7 e8 [2] 9c c4 [2] b2 e6 [2] a6 fd [2] a9 e7 [2] b7 fa [2] b5 fb [2] ae fd [2] b2 fa [2] ae d5 }

  condition:
    any of them
}