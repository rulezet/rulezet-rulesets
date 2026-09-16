rule TTP_XOR_QUAD_CurrentVersionRun_f8aa {
  strings:
    $key_f8aa = { ab c5 [2] 8f cb [2] a4 e7 [2] 8a c5 [2] 9e de [2] 91 c4 [2] 8f d9 [2] 8d d8 [2] 96 de [2] 8a d9 [2] 96 f6 }

  condition:
    any of them
}