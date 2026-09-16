rule TTP_XOR_QUAD_CurrentVersionRun_2eaa {
  strings:
    $key_2eaa = { 7d c5 [2] 59 cb [2] 72 e7 [2] 5c c5 [2] 48 de [2] 47 c4 [2] 59 d9 [2] 5b d8 [2] 40 de [2] 5c d9 [2] 40 f6 }

  condition:
    any of them
}