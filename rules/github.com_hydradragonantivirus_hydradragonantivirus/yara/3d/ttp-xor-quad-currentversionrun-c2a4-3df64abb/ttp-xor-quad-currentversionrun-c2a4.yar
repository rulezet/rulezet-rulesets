rule TTP_XOR_QUAD_CurrentVersionRun_c2a4 {
  strings:
    $key_c2a4 = { 91 cb [2] b5 c5 [2] 9e e9 [2] b0 cb [2] a4 d0 [2] ab ca [2] b5 d7 [2] b7 d6 [2] ac d0 [2] b0 d7 [2] ac f8 }

  condition:
    any of them
}