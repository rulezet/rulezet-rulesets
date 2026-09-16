rule TTP_XOR_QUAD_CurrentVersionRun_4bb9 {
  strings:
    $key_4bb9 = { 18 d6 [2] 3c d8 [2] 17 f4 [2] 39 d6 [2] 2d cd [2] 22 d7 [2] 3c ca [2] 3e cb [2] 25 cd [2] 39 ca [2] 25 e5 }

  condition:
    any of them
}