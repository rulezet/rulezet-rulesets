rule TTP_XOR_QUAD_CurrentVersionRun_0aaa {
  strings:
    $key_0aaa = { 59 c5 [2] 7d cb [2] 56 e7 [2] 78 c5 [2] 6c de [2] 63 c4 [2] 7d d9 [2] 7f d8 [2] 64 de [2] 78 d9 [2] 64 f6 }

  condition:
    any of them
}