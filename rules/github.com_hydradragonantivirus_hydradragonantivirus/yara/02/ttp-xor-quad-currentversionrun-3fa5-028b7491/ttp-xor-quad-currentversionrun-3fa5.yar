rule TTP_XOR_QUAD_CurrentVersionRun_3fa5 {
  strings:
    $key_3fa5 = { 6c ca [2] 48 c4 [2] 63 e8 [2] 4d ca [2] 59 d1 [2] 56 cb [2] 48 d6 [2] 4a d7 [2] 51 d1 [2] 4d d6 [2] 51 f9 }

  condition:
    any of them
}