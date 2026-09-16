rule TTP_XOR_QUAD_CurrentVersionRun_c1b7 {
  strings:
    $key_c1b7 = { 92 d8 [2] b6 d6 [2] 9d fa [2] b3 d8 [2] a7 c3 [2] a8 d9 [2] b6 c4 [2] b4 c5 [2] af c3 [2] b3 c4 [2] af eb }

  condition:
    any of them
}