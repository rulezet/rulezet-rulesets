rule TTP_XOR_QUAD_CurrentVersionRun_04aa {
  strings:
    $key_04aa = { 57 c5 [2] 73 cb [2] 58 e7 [2] 76 c5 [2] 62 de [2] 6d c4 [2] 73 d9 [2] 71 d8 [2] 6a de [2] 76 d9 [2] 6a f6 }

  condition:
    any of them
}