rule TTP_XOR_QUAD_CurrentVersionRun_d9b9 {
  strings:
    $key_d9b9 = { 8a d6 [2] ae d8 [2] 85 f4 [2] ab d6 [2] bf cd [2] b0 d7 [2] ae ca [2] ac cb [2] b7 cd [2] ab ca [2] b7 e5 }

  condition:
    any of them
}