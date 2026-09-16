rule TTP_XOR_MULT_DOSStub_f6bb {
  strings:
    $key_f6bb = { a2 d3 [2] d6 cb [2] 91 c9 [2] d6 d8 [2] 98 d4 [2] 94 de [2] 83 d5 [2] 98 9b [2] a5 }

  condition:
    any of them
}