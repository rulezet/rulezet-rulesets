rule TTP_XOR_QUAD_CurrentVersionRun_2fa4 {
  strings:
    $key_2fa4 = { 7c cb [2] 58 c5 [2] 73 e9 [2] 5d cb [2] 49 d0 [2] 46 ca [2] 58 d7 [2] 5a d6 [2] 41 d0 [2] 5d d7 [2] 41 f8 }

  condition:
    any of them
}