rule TTP_XOR_QUAD_CurrentVersionRun_c595 {
  strings:
    $key_c595 = { 96 fa [2] b2 f4 [2] 99 d8 [2] b7 fa [2] a3 e1 [2] ac fb [2] b2 e6 [2] b0 e7 [2] ab e1 [2] b7 e6 [2] ab c9 }

  condition:
    any of them
}