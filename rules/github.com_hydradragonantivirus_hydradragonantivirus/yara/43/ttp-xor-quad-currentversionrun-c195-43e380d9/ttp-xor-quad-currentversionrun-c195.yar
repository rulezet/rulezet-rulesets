rule TTP_XOR_QUAD_CurrentVersionRun_c195 {
  strings:
    $key_c195 = { 92 fa [2] b6 f4 [2] 9d d8 [2] b3 fa [2] a7 e1 [2] a8 fb [2] b6 e6 [2] b4 e7 [2] af e1 [2] b3 e6 [2] af c9 }

  condition:
    any of them
}