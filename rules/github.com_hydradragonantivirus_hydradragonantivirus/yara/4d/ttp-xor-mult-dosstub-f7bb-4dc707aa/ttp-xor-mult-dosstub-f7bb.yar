rule TTP_XOR_MULT_DOSStub_f7bb {
  strings:
    $key_f7bb = { a3 d3 [2] d7 cb [2] 90 c9 [2] d7 d8 [2] 99 d4 [2] 95 de [2] 82 d5 [2] 99 9b [2] a4 }

  condition:
    any of them
}