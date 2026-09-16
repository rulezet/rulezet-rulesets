rule TTP_XOR_QUAD_CurrentVersionRun_c189 {
  strings:
    $key_c189 = { 92 e6 [2] b6 e8 [2] 9d c4 [2] b3 e6 [2] a7 fd [2] a8 e7 [2] b6 fa [2] b4 fb [2] af fd [2] b3 fa [2] af d5 }

  condition:
    any of them
}