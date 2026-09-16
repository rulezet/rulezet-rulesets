rule TTP_XOR_QUAD_CurrentVersionRun_eeaa {
  strings:
    $key_eeaa = { bd c5 [2] 99 cb [2] b2 e7 [2] 9c c5 [2] 88 de [2] 87 c4 [2] 99 d9 [2] 9b d8 [2] 80 de [2] 9c d9 [2] 80 f6 }

  condition:
    any of them
}