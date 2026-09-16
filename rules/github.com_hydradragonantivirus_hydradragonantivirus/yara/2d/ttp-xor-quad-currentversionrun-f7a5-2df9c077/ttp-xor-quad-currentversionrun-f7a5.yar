rule TTP_XOR_QUAD_CurrentVersionRun_f7a5 {
  strings:
    $key_f7a5 = { a4 ca [2] 80 c4 [2] ab e8 [2] 85 ca [2] 91 d1 [2] 9e cb [2] 80 d6 [2] 82 d7 [2] 99 d1 [2] 85 d6 [2] 99 f9 }

  condition:
    any of them
}