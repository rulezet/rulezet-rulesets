rule TTP_XOR_QUAD_CurrentVersionRun_edaa {
  strings:
    $key_edaa = { be c5 [2] 9a cb [2] b1 e7 [2] 9f c5 [2] 8b de [2] 84 c4 [2] 9a d9 [2] 98 d8 [2] 83 de [2] 9f d9 [2] 83 f6 }

  condition:
    any of them
}