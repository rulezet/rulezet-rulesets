rule TTP_XOR_QUAD_CurrentVersionRun_4fa5 {
  strings:
    $key_4fa5 = { 1c ca [2] 38 c4 [2] 13 e8 [2] 3d ca [2] 29 d1 [2] 26 cb [2] 38 d6 [2] 3a d7 [2] 21 d1 [2] 3d d6 [2] 21 f9 }

  condition:
    any of them
}