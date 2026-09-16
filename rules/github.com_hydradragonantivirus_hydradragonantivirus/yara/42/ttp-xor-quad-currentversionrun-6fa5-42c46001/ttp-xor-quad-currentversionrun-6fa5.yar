rule TTP_XOR_QUAD_CurrentVersionRun_6fa5 {
  strings:
    $key_6fa5 = { 3c ca [2] 18 c4 [2] 33 e8 [2] 1d ca [2] 09 d1 [2] 06 cb [2] 18 d6 [2] 1a d7 [2] 01 d1 [2] 1d d6 [2] 01 f9 }

  condition:
    any of them
}