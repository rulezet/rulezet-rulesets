rule TTP_XOR_QUAD_CurrentVersionRun_7bb9 {
  strings:
    $key_7bb9 = { 28 d6 [2] 0c d8 [2] 27 f4 [2] 09 d6 [2] 1d cd [2] 12 d7 [2] 0c ca [2] 0e cb [2] 15 cd [2] 09 ca [2] 15 e5 }

  condition:
    any of them
}