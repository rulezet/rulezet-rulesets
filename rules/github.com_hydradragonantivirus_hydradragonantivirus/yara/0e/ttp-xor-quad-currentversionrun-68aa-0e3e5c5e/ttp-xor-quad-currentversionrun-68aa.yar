rule TTP_XOR_QUAD_CurrentVersionRun_68aa {
  strings:
    $key_68aa = { 3b c5 [2] 1f cb [2] 34 e7 [2] 1a c5 [2] 0e de [2] 01 c4 [2] 1f d9 [2] 1d d8 [2] 06 de [2] 1a d9 [2] 06 f6 }

  condition:
    any of them
}