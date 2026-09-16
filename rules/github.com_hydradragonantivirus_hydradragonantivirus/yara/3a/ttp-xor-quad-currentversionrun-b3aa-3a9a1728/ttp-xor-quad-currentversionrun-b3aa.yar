rule TTP_XOR_QUAD_CurrentVersionRun_b3aa {
  strings:
    $key_b3aa = { e0 c5 [2] c4 cb [2] ef e7 [2] c1 c5 [2] d5 de [2] da c4 [2] c4 d9 [2] c6 d8 [2] dd de [2] c1 d9 [2] dd f6 }

  condition:
    any of them
}