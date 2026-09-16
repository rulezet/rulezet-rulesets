rule TTP_XOR_QUAD_CurrentVersionRun_0bb9 {
  strings:
    $key_0bb9 = { 58 d6 [2] 7c d8 [2] 57 f4 [2] 79 d6 [2] 6d cd [2] 62 d7 [2] 7c ca [2] 7e cb [2] 65 cd [2] 79 ca [2] 65 e5 }

  condition:
    any of them
}