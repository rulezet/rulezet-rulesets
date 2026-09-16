rule TTP_XOR_QUAD_CurrentVersionRun_18aa {
  strings:
    $key_18aa = { 4b c5 [2] 6f cb [2] 44 e7 [2] 6a c5 [2] 7e de [2] 71 c4 [2] 6f d9 [2] 6d d8 [2] 76 de [2] 6a d9 [2] 76 f6 }

  condition:
    any of them
}