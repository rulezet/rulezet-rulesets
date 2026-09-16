rule TTP_XOR_QUAD_CurrentVersionRun_c5a4 {
  strings:
    $key_c5a4 = { 96 cb [2] b2 c5 [2] 99 e9 [2] b7 cb [2] a3 d0 [2] ac ca [2] b2 d7 [2] b0 d6 [2] ab d0 [2] b7 d7 [2] ab f8 }

  condition:
    any of them
}