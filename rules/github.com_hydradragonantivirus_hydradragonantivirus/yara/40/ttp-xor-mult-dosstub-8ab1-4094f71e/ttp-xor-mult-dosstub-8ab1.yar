rule TTP_XOR_MULT_DOSStub_8ab1 {
  strings:
    $key_8ab1 = { de d9 [2] aa c1 [2] ed c3 [2] aa d2 [2] e4 de [2] e8 d4 [2] ff df [2] e4 91 [2] d9 }

  condition:
    any of them
}