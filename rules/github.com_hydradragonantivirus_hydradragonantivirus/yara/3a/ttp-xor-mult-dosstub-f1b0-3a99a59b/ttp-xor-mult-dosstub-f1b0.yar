rule TTP_XOR_MULT_DOSStub_f1b0 {
  strings:
    $key_f1b0 = { a5 d8 [2] d1 c0 [2] 96 c2 [2] d1 d3 [2] 9f df [2] 93 d5 [2] 84 de [2] 9f 90 [2] a2 }

  condition:
    any of them
}