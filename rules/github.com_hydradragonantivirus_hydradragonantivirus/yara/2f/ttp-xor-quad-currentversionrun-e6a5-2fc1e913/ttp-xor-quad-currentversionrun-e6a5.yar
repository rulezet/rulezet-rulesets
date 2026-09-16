rule TTP_XOR_QUAD_CurrentVersionRun_e6a5 {
  strings:
    $key_e6a5 = { b5 ca [2] 91 c4 [2] ba e8 [2] 94 ca [2] 80 d1 [2] 8f cb [2] 91 d6 [2] 93 d7 [2] 88 d1 [2] 94 d6 [2] 88 f9 }

  condition:
    any of them
}