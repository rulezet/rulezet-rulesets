rule TTP_XOR_QUAD_CurrentVersionRun_c7b8 {
  strings:
    $key_c7b8 = { 94 d7 [2] b0 d9 [2] 9b f5 [2] b5 d7 [2] a1 cc [2] ae d6 [2] b0 cb [2] b2 ca [2] a9 cc [2] b5 cb [2] a9 e4 }

  condition:
    any of them
}