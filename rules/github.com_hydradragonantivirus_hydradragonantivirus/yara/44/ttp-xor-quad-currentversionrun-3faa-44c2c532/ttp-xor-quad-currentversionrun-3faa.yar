rule TTP_XOR_QUAD_CurrentVersionRun_3faa {
  strings:
    $key_3faa = { 6c c5 [2] 48 cb [2] 63 e7 [2] 4d c5 [2] 59 de [2] 56 c4 [2] 48 d9 [2] 4a d8 [2] 51 de [2] 4d d9 [2] 51 f6 }

  condition:
    any of them
}