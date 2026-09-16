rule TTP_XOR_QUAD_CurrentVersionRun_36a5 {
  strings:
    $key_36a5 = { 65 ca [2] 41 c4 [2] 6a e8 [2] 44 ca [2] 50 d1 [2] 5f cb [2] 41 d6 [2] 43 d7 [2] 58 d1 [2] 44 d6 [2] 58 f9 }

  condition:
    any of them
}