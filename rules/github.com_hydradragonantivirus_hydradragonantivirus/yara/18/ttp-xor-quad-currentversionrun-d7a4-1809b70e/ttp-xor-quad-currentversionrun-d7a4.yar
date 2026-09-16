rule TTP_XOR_QUAD_CurrentVersionRun_d7a4 {
  strings:
    $key_d7a4 = { 84 cb [2] a0 c5 [2] 8b e9 [2] a5 cb [2] b1 d0 [2] be ca [2] a0 d7 [2] a2 d6 [2] b9 d0 [2] a5 d7 [2] b9 f8 }

  condition:
    any of them
}