rule TTP_XOR_QUAD_CurrentVersionRun_c789 {
  strings:
    $key_c789 = { 94 e6 [2] b0 e8 [2] 9b c4 [2] b5 e6 [2] a1 fd [2] ae e7 [2] b0 fa [2] b2 fb [2] a9 fd [2] b5 fa [2] a9 d5 }

  condition:
    any of them
}