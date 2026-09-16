rule TTP_XOR_QUAD_CurrentVersionRun_d9a4 {
  strings:
    $key_d9a4 = { 8a cb [2] ae c5 [2] 85 e9 [2] ab cb [2] bf d0 [2] b0 ca [2] ae d7 [2] ac d6 [2] b7 d0 [2] ab d7 [2] b7 f8 }

  condition:
    any of them
}