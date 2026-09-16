rule TTP_XOR_QUAD_CurrentVersionRun_4ea5 {
  strings:
    $key_4ea5 = { 1d ca [2] 39 c4 [2] 12 e8 [2] 3c ca [2] 28 d1 [2] 27 cb [2] 39 d6 [2] 3b d7 [2] 20 d1 [2] 3c d6 [2] 20 f9 }

  condition:
    any of them
}