rule TTP_XOR_MULT_DOSStub_f3b1 {
  strings:
    $key_f3b1 = { a7 d9 [2] d3 c1 [2] 94 c3 [2] d3 d2 [2] 9d de [2] 91 d4 [2] 86 df [2] 9d 91 [2] a0 }

  condition:
    any of them
}