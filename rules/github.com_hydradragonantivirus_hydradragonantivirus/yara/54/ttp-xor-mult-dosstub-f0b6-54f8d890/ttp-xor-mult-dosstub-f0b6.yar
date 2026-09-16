rule TTP_XOR_MULT_DOSStub_f0b6 {
  strings:
    $key_f0b6 = { a4 de [2] d0 c6 [2] 97 c4 [2] d0 d5 [2] 9e d9 [2] 92 d3 [2] 85 d8 [2] 9e 96 [2] a3 }

  condition:
    any of them
}