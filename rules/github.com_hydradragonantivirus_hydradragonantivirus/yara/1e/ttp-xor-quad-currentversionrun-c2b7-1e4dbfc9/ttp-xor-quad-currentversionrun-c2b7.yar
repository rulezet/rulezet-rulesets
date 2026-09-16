rule TTP_XOR_QUAD_CurrentVersionRun_c2b7 {
  strings:
    $key_c2b7 = { 91 d8 [2] b5 d6 [2] 9e fa [2] b0 d8 [2] a4 c3 [2] ab d9 [2] b5 c4 [2] b7 c5 [2] ac c3 [2] b0 c4 [2] ac eb }

  condition:
    any of them
}