rule TTP_XOR_MULT_DOSStub_f5b0 {
  strings:
    $key_f5b0 = { a1 d8 [2] d5 c0 [2] 92 c2 [2] d5 d3 [2] 9b df [2] 97 d5 [2] 80 de [2] 9b 90 [2] a6 }

  condition:
    any of them
}