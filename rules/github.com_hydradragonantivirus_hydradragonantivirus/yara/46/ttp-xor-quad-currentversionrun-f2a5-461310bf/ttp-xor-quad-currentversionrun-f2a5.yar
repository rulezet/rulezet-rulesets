rule TTP_XOR_QUAD_CurrentVersionRun_f2a5 {
  strings:
    $key_f2a5 = { a1 ca [2] 85 c4 [2] ae e8 [2] 80 ca [2] 94 d1 [2] 9b cb [2] 85 d6 [2] 87 d7 [2] 9c d1 [2] 80 d6 [2] 9c f9 }

  condition:
    any of them
}