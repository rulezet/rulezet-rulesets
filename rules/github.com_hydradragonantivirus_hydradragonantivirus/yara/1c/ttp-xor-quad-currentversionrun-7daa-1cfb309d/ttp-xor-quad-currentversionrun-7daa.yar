rule TTP_XOR_QUAD_CurrentVersionRun_7daa {
  strings:
    $key_7daa = { 2e c5 [2] 0a cb [2] 21 e7 [2] 0f c5 [2] 1b de [2] 14 c4 [2] 0a d9 [2] 08 d8 [2] 13 de [2] 0f d9 [2] 13 f6 }

  condition:
    any of them
}