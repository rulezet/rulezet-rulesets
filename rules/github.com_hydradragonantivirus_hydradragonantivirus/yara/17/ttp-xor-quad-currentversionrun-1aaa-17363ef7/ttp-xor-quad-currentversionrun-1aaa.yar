rule TTP_XOR_QUAD_CurrentVersionRun_1aaa {
  strings:
    $key_1aaa = { 49 c5 [2] 6d cb [2] 46 e7 [2] 68 c5 [2] 7c de [2] 73 c4 [2] 6d d9 [2] 6f d8 [2] 74 de [2] 68 d9 [2] 74 f6 }

  condition:
    any of them
}