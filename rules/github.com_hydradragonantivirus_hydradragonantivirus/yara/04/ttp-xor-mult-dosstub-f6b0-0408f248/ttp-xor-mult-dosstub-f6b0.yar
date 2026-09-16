rule TTP_XOR_MULT_DOSStub_f6b0 {
  strings:
    $key_f6b0 = { a2 d8 [2] d6 c0 [2] 91 c2 [2] d6 d3 [2] 98 df [2] 94 d5 [2] 83 de [2] 98 90 [2] a5 }

  condition:
    any of them
}