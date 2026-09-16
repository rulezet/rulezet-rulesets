rule TTP_XOR_QUAD_CurrentVersionRun_daaa {
  strings:
    $key_daaa = { 89 c5 [2] ad cb [2] 86 e7 [2] a8 c5 [2] bc de [2] b3 c4 [2] ad d9 [2] af d8 [2] b4 de [2] a8 d9 [2] b4 f6 }

  condition:
    any of them
}