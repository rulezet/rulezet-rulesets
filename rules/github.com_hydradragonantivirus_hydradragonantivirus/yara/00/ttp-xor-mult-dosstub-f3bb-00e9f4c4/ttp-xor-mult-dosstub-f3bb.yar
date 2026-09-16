rule TTP_XOR_MULT_DOSStub_f3bb {
  strings:
    $key_f3bb = { a7 d3 [2] d3 cb [2] 94 c9 [2] d3 d8 [2] 9d d4 [2] 91 de [2] 86 d5 [2] 9d 9b [2] a0 }

  condition:
    any of them
}