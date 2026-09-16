rule TTP_XOR_QUAD_CurrentVersionRun_08aa {
  strings:
    $key_08aa = { 5b c5 [2] 7f cb [2] 54 e7 [2] 7a c5 [2] 6e de [2] 61 c4 [2] 7f d9 [2] 7d d8 [2] 66 de [2] 7a d9 [2] 66 f6 }

  condition:
    any of them
}