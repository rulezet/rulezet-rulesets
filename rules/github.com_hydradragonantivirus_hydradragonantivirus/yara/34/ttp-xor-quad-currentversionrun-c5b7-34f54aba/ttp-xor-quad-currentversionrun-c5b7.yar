rule TTP_XOR_QUAD_CurrentVersionRun_c5b7 {
  strings:
    $key_c5b7 = { 96 d8 [2] b2 d6 [2] 99 fa [2] b7 d8 [2] a3 c3 [2] ac d9 [2] b2 c4 [2] b0 c5 [2] ab c3 [2] b7 c4 [2] ab eb }

  condition:
    any of them
}