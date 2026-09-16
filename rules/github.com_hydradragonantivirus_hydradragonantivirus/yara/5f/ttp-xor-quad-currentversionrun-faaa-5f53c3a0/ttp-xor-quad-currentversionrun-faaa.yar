rule TTP_XOR_QUAD_CurrentVersionRun_faaa {
  strings:
    $key_faaa = { a9 c5 [2] 8d cb [2] a6 e7 [2] 88 c5 [2] 9c de [2] 93 c4 [2] 8d d9 [2] 8f d8 [2] 94 de [2] 88 d9 [2] 94 f6 }

  condition:
    any of them
}