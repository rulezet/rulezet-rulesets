rule TTP_XOR_QUAD_CurrentVersionRun_d989 {
  strings:
    $key_d989 = { 8a e6 [2] ae e8 [2] 85 c4 [2] ab e6 [2] bf fd [2] b0 e7 [2] ae fa [2] ac fb [2] b7 fd [2] ab fa [2] b7 d5 }

  condition:
    any of them
}