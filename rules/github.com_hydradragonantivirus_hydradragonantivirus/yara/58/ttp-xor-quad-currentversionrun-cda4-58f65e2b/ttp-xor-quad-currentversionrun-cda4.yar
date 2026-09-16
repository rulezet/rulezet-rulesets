rule TTP_XOR_QUAD_CurrentVersionRun_cda4 {
  strings:
    $key_cda4 = { 9e cb [2] ba c5 [2] 91 e9 [2] bf cb [2] ab d0 [2] a4 ca [2] ba d7 [2] b8 d6 [2] a3 d0 [2] bf d7 [2] a3 f8 }

  condition:
    any of them
}