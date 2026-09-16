rule TTP_XOR_QUAD_CurrentVersionRun_d9a5 {
  strings:
    $key_d9a5 = { 8a ca [2] ae c4 [2] 85 e8 [2] ab ca [2] bf d1 [2] b0 cb [2] ae d6 [2] ac d7 [2] b7 d1 [2] ab d6 [2] b7 f9 }

  condition:
    any of them
}