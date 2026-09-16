rule TTP_XOR_QUAD_CurrentVersionRun_c2a5 {
  strings:
    $key_c2a5 = { 91 ca [2] b5 c4 [2] 9e e8 [2] b0 ca [2] a4 d1 [2] ab cb [2] b5 d6 [2] b7 d7 [2] ac d1 [2] b0 d6 [2] ac f9 }

  condition:
    any of them
}