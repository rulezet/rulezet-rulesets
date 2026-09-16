rule TTP_XOR_QUAD_CurrentVersionRun_0daa {
  strings:
    $key_0daa = { 5e c5 [2] 7a cb [2] 51 e7 [2] 7f c5 [2] 6b de [2] 64 c4 [2] 7a d9 [2] 78 d8 [2] 63 de [2] 7f d9 [2] 63 f6 }

  condition:
    any of them
}