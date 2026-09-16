rule TTP_XOR_QUAD_CurrentVersionRun_cdb8 {
  strings:
    $key_cdb8 = { 9e d7 [2] ba d9 [2] 91 f5 [2] bf d7 [2] ab cc [2] a4 d6 [2] ba cb [2] b8 ca [2] a3 cc [2] bf cb [2] a3 e4 }

  condition:
    any of them
}