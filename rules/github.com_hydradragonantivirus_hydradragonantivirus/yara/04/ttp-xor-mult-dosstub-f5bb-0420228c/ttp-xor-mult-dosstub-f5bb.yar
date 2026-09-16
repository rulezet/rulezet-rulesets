rule TTP_XOR_MULT_DOSStub_f5bb {
  strings:
    $key_f5bb = { a1 d3 [2] d5 cb [2] 92 c9 [2] d5 d8 [2] 9b d4 [2] 97 de [2] 80 d5 [2] 9b 9b [2] a6 }

  condition:
    any of them
}