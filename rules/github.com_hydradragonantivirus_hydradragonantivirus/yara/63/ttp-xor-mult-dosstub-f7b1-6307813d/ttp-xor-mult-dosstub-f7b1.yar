rule TTP_XOR_MULT_DOSStub_f7b1 {
  strings:
    $key_f7b1 = { a3 d9 [2] d7 c1 [2] 90 c3 [2] d7 d2 [2] 99 de [2] 95 d4 [2] 82 df [2] 99 91 [2] a4 }

  condition:
    any of them
}