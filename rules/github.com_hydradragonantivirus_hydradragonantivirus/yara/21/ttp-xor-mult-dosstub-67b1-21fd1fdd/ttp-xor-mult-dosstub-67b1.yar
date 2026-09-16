rule TTP_XOR_MULT_DOSStub_67b1 {
  strings:
    $key_67b1 = { 33 d9 [2] 47 c1 [2] 00 c3 [2] 47 d2 [2] 09 de [2] 05 d4 [2] 12 df [2] 09 91 [2] 34 }

  condition:
    any of them
}