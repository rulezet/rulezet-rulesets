rule TTP_XOR_MULT_DOSStub_f2b6 {
  strings:
    $key_f2b6 = { a6 de [2] d2 c6 [2] 95 c4 [2] d2 d5 [2] 9c d9 [2] 90 d3 [2] 87 d8 [2] 9c 96 [2] a1 }

  condition:
    any of them
}