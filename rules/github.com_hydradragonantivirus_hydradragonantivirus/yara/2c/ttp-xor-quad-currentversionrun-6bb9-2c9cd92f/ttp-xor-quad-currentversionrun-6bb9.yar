rule TTP_XOR_QUAD_CurrentVersionRun_6bb9 {
  strings:
    $key_6bb9 = { 38 d6 [2] 1c d8 [2] 37 f4 [2] 19 d6 [2] 0d cd [2] 02 d7 [2] 1c ca [2] 1e cb [2] 05 cd [2] 19 ca [2] 05 e5 }

  condition:
    any of them
}