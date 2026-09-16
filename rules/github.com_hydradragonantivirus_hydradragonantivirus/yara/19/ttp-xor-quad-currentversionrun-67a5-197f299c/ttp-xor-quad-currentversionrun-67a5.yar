rule TTP_XOR_QUAD_CurrentVersionRun_67a5 {
  strings:
    $key_67a5 = { 34 ca [2] 10 c4 [2] 3b e8 [2] 15 ca [2] 01 d1 [2] 0e cb [2] 10 d6 [2] 12 d7 [2] 09 d1 [2] 15 d6 [2] 09 f9 }

  condition:
    any of them
}