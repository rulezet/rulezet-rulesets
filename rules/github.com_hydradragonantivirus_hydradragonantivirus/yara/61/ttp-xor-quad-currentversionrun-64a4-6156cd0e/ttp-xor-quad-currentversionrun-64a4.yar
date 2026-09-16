rule TTP_XOR_QUAD_CurrentVersionRun_64a4 {
  strings:
    $key_64a4 = { 37 cb [2] 13 c5 [2] 38 e9 [2] 16 cb [2] 02 d0 [2] 0d ca [2] 13 d7 [2] 11 d6 [2] 0a d0 [2] 16 d7 [2] 0a f8 }

  condition:
    any of them
}