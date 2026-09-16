rule TTP_XOR_QUAD_CurrentVersionRun_5fa5 {
  strings:
    $key_5fa5 = { 0c ca [2] 28 c4 [2] 03 e8 [2] 2d ca [2] 39 d1 [2] 36 cb [2] 28 d6 [2] 2a d7 [2] 31 d1 [2] 2d d6 [2] 31 f9 }

  condition:
    any of them
}