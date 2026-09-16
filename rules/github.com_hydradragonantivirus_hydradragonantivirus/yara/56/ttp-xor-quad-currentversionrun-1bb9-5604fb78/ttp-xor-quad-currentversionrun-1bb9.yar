rule TTP_XOR_QUAD_CurrentVersionRun_1bb9 {
  strings:
    $key_1bb9 = { 48 d6 [2] 6c d8 [2] 47 f4 [2] 69 d6 [2] 7d cd [2] 72 d7 [2] 6c ca [2] 6e cb [2] 75 cd [2] 69 ca [2] 75 e5 }

  condition:
    any of them
}