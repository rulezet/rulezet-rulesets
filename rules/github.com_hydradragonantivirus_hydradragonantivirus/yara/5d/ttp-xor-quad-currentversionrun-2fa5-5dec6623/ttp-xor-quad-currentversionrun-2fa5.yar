rule TTP_XOR_QUAD_CurrentVersionRun_2fa5 {
  strings:
    $key_2fa5 = { 7c ca [2] 58 c4 [2] 73 e8 [2] 5d ca [2] 49 d1 [2] 46 cb [2] 58 d6 [2] 5a d7 [2] 41 d1 [2] 5d d6 [2] 41 f9 }

  condition:
    any of them
}