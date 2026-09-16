rule TTP_XOR_QUAD_CurrentVersionRun_6aaa {
  strings:
    $key_6aaa = { 39 c5 [2] 1d cb [2] 36 e7 [2] 18 c5 [2] 0c de [2] 03 c4 [2] 1d d9 [2] 1f d8 [2] 04 de [2] 18 d9 [2] 04 f6 }

  condition:
    any of them
}