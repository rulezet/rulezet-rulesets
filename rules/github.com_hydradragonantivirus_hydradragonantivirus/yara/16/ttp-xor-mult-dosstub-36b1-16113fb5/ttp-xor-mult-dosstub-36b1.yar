rule TTP_XOR_MULT_DOSStub_36b1 {
  strings:
    $key_36b1 = { 62 d9 [2] 16 c1 [2] 51 c3 [2] 16 d2 [2] 58 de [2] 54 d4 [2] 43 df [2] 58 91 [2] 65 }

  condition:
    any of them
}