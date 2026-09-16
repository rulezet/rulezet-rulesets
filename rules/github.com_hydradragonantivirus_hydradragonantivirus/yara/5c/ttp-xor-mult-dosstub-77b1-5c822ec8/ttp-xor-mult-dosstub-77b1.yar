rule TTP_XOR_MULT_DOSStub_77b1 {
  strings:
    $key_77b1 = { 23 d9 [2] 57 c1 [2] 10 c3 [2] 57 d2 [2] 19 de [2] 15 d4 [2] 02 df [2] 19 91 [2] 24 }

  condition:
    any of them
}