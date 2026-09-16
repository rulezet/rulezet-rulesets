rule TTP_XOR_QUAD_CurrentVersionRun_7faa {
  strings:
    $key_7faa = { 2c c5 [2] 08 cb [2] 23 e7 [2] 0d c5 [2] 19 de [2] 16 c4 [2] 08 d9 [2] 0a d8 [2] 11 de [2] 0d d9 [2] 11 f6 }

  condition:
    any of them
}