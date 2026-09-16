rule TTP_XOR_QUAD_CurrentVersionRun_c1b6 {
  strings:
    $key_c1b6 = { 92 d9 [2] b6 d7 [2] 9d fb [2] b3 d9 [2] a7 c2 [2] a8 d8 [2] b6 c5 [2] b4 c4 [2] af c2 [2] b3 c5 [2] af ea }

  condition:
    any of them
}