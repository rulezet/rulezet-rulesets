rule TTP_XOR_MULT_DOSStub_f0b0 {
  strings:
    $key_f0b0 = { a4 d8 [2] d0 c0 [2] 97 c2 [2] d0 d3 [2] 9e df [2] 92 d5 [2] 85 de [2] 9e 90 [2] a3 }

  condition:
    any of them
}