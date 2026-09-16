rule TTP_XOR_QUAD_CurrentVersionRun_f3aa {
  strings:
    $key_f3aa = { a0 c5 [2] 84 cb [2] af e7 [2] 81 c5 [2] 95 de [2] 9a c4 [2] 84 d9 [2] 86 d8 [2] 9d de [2] 81 d9 [2] 9d f6 }

  condition:
    any of them
}