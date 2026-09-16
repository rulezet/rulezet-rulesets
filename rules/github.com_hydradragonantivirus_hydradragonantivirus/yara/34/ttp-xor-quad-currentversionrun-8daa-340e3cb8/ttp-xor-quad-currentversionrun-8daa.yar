rule TTP_XOR_QUAD_CurrentVersionRun_8daa {
  strings:
    $key_8daa = { de c5 [2] fa cb [2] d1 e7 [2] ff c5 [2] eb de [2] e4 c4 [2] fa d9 [2] f8 d8 [2] e3 de [2] ff d9 [2] e3 f6 }

  condition:
    any of them
}