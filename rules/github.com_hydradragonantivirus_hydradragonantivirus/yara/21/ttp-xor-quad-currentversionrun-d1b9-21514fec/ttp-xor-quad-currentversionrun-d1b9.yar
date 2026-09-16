rule TTP_XOR_QUAD_CurrentVersionRun_d1b9 {
  strings:
    $key_d1b9 = { 82 d6 [2] a6 d8 [2] 8d f4 [2] a3 d6 [2] b7 cd [2] b8 d7 [2] a6 ca [2] a4 cb [2] bf cd [2] a3 ca [2] bf e5 }

  condition:
    any of them
}