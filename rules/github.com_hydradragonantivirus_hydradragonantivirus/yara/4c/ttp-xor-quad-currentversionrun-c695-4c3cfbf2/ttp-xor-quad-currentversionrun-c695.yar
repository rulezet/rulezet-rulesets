rule TTP_XOR_QUAD_CurrentVersionRun_c695 {
  strings:
    $key_c695 = { 95 fa [2] b1 f4 [2] 9a d8 [2] b4 fa [2] a0 e1 [2] af fb [2] b1 e6 [2] b3 e7 [2] a8 e1 [2] b4 e6 [2] a8 c9 }

  condition:
    any of them
}