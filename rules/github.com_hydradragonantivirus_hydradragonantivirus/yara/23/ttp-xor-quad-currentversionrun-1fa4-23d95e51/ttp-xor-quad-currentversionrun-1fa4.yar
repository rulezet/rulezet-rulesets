rule TTP_XOR_QUAD_CurrentVersionRun_1fa4 {
  strings:
    $key_1fa4 = { 4c cb [2] 68 c5 [2] 43 e9 [2] 6d cb [2] 79 d0 [2] 76 ca [2] 68 d7 [2] 6a d6 [2] 71 d0 [2] 6d d7 [2] 71 f8 }

  condition:
    any of them
}