rule TTP_XOR_MULT_DOSStub_7ab1 {
  strings:
    $key_7ab1 = { 2e d9 [2] 5a c1 [2] 1d c3 [2] 5a d2 [2] 14 de [2] 18 d4 [2] 0f df [2] 14 91 [2] 29 }

  condition:
    any of them
}